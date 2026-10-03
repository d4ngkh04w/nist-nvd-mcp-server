import { randomBytes } from 'node:crypto';
import type { Dirent, Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { mkdir, open, readFile, readdir, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';

import { CACHE_RESOURCE_DIRECTORIES, CACHE_TMP_DIRECTORY } from '../../config/defaults.js';
import { CACHE_RESOURCE_DIRECTORY, type CacheResource } from '../../domain/cache.js';
import { byteLength, safeJsonParse } from '../../shared/json.js';
import type { Logger } from '../../shared/logger.js';

/** Envelope persisted next to every cached payload. */
export type DiskCacheEnvelope<T> = {
  version: number;
  resource: CacheResource;
  queryHash: string;
  createdAt: string;
  expiresAt: string;
  payload: T;
};

export type DiskCacheCleanupStats = {
  scannedFiles: number;
  removedFiles: number;
  freedBytes: number;
  totalBytes: number;
};

export type DiskCacheOptions = {
  directory: string;
  envelopeVersion: number;
  maxEntryBytes: number;
  logger: Logger;
  /** Injectable clock, used for expiry decisions during cleanup. */
  now?: () => Date;
};

const DISK_KEY_PATTERN = /^[a-f0-9]{64}$/;
const PREFIXED_DISK_KEY_PATTERN = /^sha256:([a-f0-9]{64})$/;
const QUERY_HASH_PREFIX = 'sha256:';
const ENTRY_EXTENSION = '.json';
const TMP_EXTENSION = '.tmp';
/** Abandoned atomic-write temp files are removed after one hour. */
const STALE_TMP_AGE_MS = 3_600_000;

type CacheFile = {
  filePath: string;
  size: number;
  mtimeMs: number;
};

/**
 * File-based cache with an atomic write path.
 *
 * Every file name is derived from a validated 64-hex digest, so no input can inject a path.
 * Cache payloads are treated as opaque: they are never logged and corruption never throws.
 */
export class DiskCache {
  private readonly directory: string;
  private readonly tmpDirectory: string;
  private readonly envelopeVersion: number;
  private readonly maxEntryBytes: number;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(options: DiskCacheOptions) {
    this.directory = options.directory;
    this.tmpDirectory = path.join(options.directory, CACHE_TMP_DIRECTORY);
    this.envelopeVersion = options.envelopeVersion;
    this.maxEntryBytes = options.maxEntryBytes;
    this.logger = options.logger;
    this.now = options.now ?? (() => new Date());
  }

  async ensureDirectories(): Promise<void> {
    await mkdir(this.tmpDirectory, { recursive: true });
    await Promise.all(
      CACHE_RESOURCE_DIRECTORIES.map((directoryName) =>
        mkdir(path.join(this.directory, directoryName), { recursive: true }),
      ),
    );
  }

  async read<T>(resource: CacheResource, key: string): Promise<DiskCacheEnvelope<T> | null> {
    const diskKey = toDiskKey(key);
    if (diskKey === null) {
      this.logger.warn('cache_key_rejected', { resource, reason: 'invalid_key_format' });
      return null;
    }

    const filePath = this.entryPath(resource, diskKey);
    let fileStat: Stats;
    try {
      fileStat = await stat(filePath);
    } catch (error) {
      if (!isNotFoundError(error)) {
        this.logger.debug('cache_read_failed', { resource, error });
      }
      return null;
    }

    if (!fileStat.isFile()) {
      return null;
    }
    if (fileStat.size > this.maxEntryBytes) {
      this.logger.warn('cache_entry_oversized', {
        resource,
        bytes: fileStat.size,
        maxEntryBytes: this.maxEntryBytes,
      });
      await this.removeFile(filePath);
      return null;
    }

    let text: string;
    try {
      text = await readFile(filePath, 'utf8');
    } catch (error) {
      if (!isNotFoundError(error)) {
        this.logger.debug('cache_read_failed', { resource, error });
      }
      return null;
    }

    const parsed = safeJsonParse<unknown>(text);
    if (!parsed.ok || !isEnvelopeFor(parsed.value, resource, diskKey, this.envelopeVersion)) {
      this.logger.warn('cache_corrupted', { resource });
      await this.removeFile(filePath);
      return null;
    }
    // The envelope shape was validated above; the payload type is fixed at this call site.
    return parsed.value as DiskCacheEnvelope<T>;
  }

  async write<T>(envelope: DiskCacheEnvelope<T>): Promise<boolean> {
    const diskKey = toDiskKey(envelope.queryHash);
    if (diskKey === null) {
      this.logger.warn('cache_write_failed', {
        resource: envelope.resource,
        reason: 'invalid_query_hash',
      });
      return false;
    }

    let json: string;
    try {
      json = JSON.stringify(envelope);
    } catch (error) {
      this.logger.warn('cache_write_failed', { resource: envelope.resource, error });
      return false;
    }

    const bytes = byteLength(json);
    if (bytes > this.maxEntryBytes) {
      this.logger.warn('cache_entry_skipped', {
        resource: envelope.resource,
        queryHash: envelope.queryHash,
        bytes,
        maxEntryBytes: this.maxEntryBytes,
      });
      return false;
    }

    const targetPath = this.entryPath(envelope.resource, diskKey);
    const tmpPath = path.join(
      this.tmpDirectory,
      `${diskKey}.${randomBytes(8).toString('hex')}${TMP_EXTENSION}`,
    );

    let handle: FileHandle | undefined;
    try {
      await mkdir(path.dirname(targetPath), { recursive: true });
      await mkdir(this.tmpDirectory, { recursive: true });
      handle = await open(tmpPath, 'w');
      await handle.writeFile(json, 'utf8');
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(tmpPath, targetPath);
      return true;
    } catch (error) {
      if (handle !== undefined) {
        try {
          await handle.close();
        } catch (closeError) {
          this.logger.debug('cache_write_close_failed', { error: closeError });
        }
      }
      await this.removeFile(tmpPath);
      this.logger.warn('cache_write_failed', { resource: envelope.resource, error });
      return false;
    }
  }

  async remove(resource: CacheResource, key: string): Promise<void> {
    const diskKey = toDiskKey(key);
    if (diskKey === null) {
      this.logger.warn('cache_key_rejected', { resource, reason: 'invalid_key_format' });
      return;
    }
    await this.removeFile(this.entryPath(resource, diskKey));
  }

  /**
   * Deletes expired/stale entries, then trims the cache by total size (oldest mtime first),
   * and finally removes abandoned atomic-write temp files. Per-file failures are logged at
   * debug level and never abort the sweep.
   */
  async cleanup(options: { maxBytes: number; maxAgeMs: number }): Promise<DiskCacheCleanupStats> {
    const nowMs = this.now().getTime();
    const maxAgeMs = options.maxAgeMs > 0 ? options.maxAgeMs : Number.POSITIVE_INFINITY;
    const maxBytes = options.maxBytes >= 0 ? options.maxBytes : Number.POSITIVE_INFINITY;

    let scannedFiles = 0;
    let removedFiles = 0;
    let freedBytes = 0;
    const survivors: CacheFile[] = [];

    for (const directoryName of CACHE_RESOURCE_DIRECTORIES) {
      const directoryPath = path.join(this.directory, directoryName);
      const entries = await this.readDirectoryEntries(directoryPath, directoryName);
      for (const entry of entries) {
        if (!entry.isFile()) {
          continue;
        }
        scannedFiles += 1;
        const filePath = path.join(directoryPath, entry.name);
        const fileStat = await this.safeStat(filePath);
        if (fileStat === null) {
          continue;
        }
        const tooOld = nowMs - fileStat.mtimeMs > maxAgeMs;
        const expired =
          fileStat.size > this.maxEntryBytes ||
          (entry.name.endsWith(ENTRY_EXTENSION) && (await this.isExpiredEnvelope(filePath, nowMs)));
        if (tooOld || expired) {
          if (await this.removeFile(filePath)) {
            removedFiles += 1;
            freedBytes += fileStat.size;
          }
          continue;
        }
        survivors.push({ filePath, size: fileStat.size, mtimeMs: fileStat.mtimeMs });
      }
    }

    let totalBytes = survivors.reduce((sum, file) => sum + file.size, 0);
    if (totalBytes > maxBytes) {
      survivors.sort(
        (left, right) => left.mtimeMs - right.mtimeMs || left.filePath.localeCompare(right.filePath),
      );
      for (const file of survivors) {
        if (totalBytes <= maxBytes) {
          break;
        }
        if (await this.removeFile(file.filePath)) {
          removedFiles += 1;
          freedBytes += file.size;
          totalBytes -= file.size;
        }
      }
    }

    const tmp = await this.cleanupTmp(nowMs);
    removedFiles += tmp.removedFiles;
    freedBytes += tmp.freedBytes;

    return { scannedFiles, removedFiles, freedBytes, totalBytes };
  }

  async stats(): Promise<{ files: number; totalBytes: number }> {
    let files = 0;
    let totalBytes = 0;
    for (const directoryName of CACHE_RESOURCE_DIRECTORIES) {
      const directoryPath = path.join(this.directory, directoryName);
      const entries = await this.readDirectoryEntries(directoryPath, directoryName);
      for (const entry of entries) {
        if (!entry.isFile()) {
          continue;
        }
        const fileStat = await this.safeStat(path.join(directoryPath, entry.name));
        if (fileStat === null) {
          continue;
        }
        files += 1;
        totalBytes += fileStat.size;
      }
    }
    return { files, totalBytes };
  }

  private entryPath(resource: CacheResource, diskKey: string): string {
    return path.join(this.directory, CACHE_RESOURCE_DIRECTORY[resource], `${diskKey}${ENTRY_EXTENSION}`);
  }

  /** Treats a missing `expiresAt` or unparseable envelope as expired (corrupt data must not linger). */
  private async isExpiredEnvelope(filePath: string, nowMs: number): Promise<boolean> {
    let text: string;
    try {
      text = await readFile(filePath, 'utf8');
    } catch (error) {
      this.logger.debug('cache_cleanup_read_failed', { error });
      return false;
    }
    const parsed = safeJsonParse<unknown>(text);
    if (!parsed.ok || !isRecord(parsed.value)) {
      return true;
    }
    const expiresAt = parsed.value['expiresAt'];
    if (typeof expiresAt !== 'string') {
      return true;
    }
    const expiresMs = Date.parse(expiresAt);
    return Number.isNaN(expiresMs) || expiresMs <= nowMs;
  }

  private async cleanupTmp(nowMs: number): Promise<{ removedFiles: number; freedBytes: number }> {
    let removedFiles = 0;
    let freedBytes = 0;
    const entries = await this.readDirectoryEntries(this.tmpDirectory, CACHE_TMP_DIRECTORY);
    for (const entry of entries) {
      if (!entry.isFile()) {
        continue;
      }
      const filePath = path.join(this.tmpDirectory, entry.name);
      const fileStat = await this.safeStat(filePath);
      if (fileStat === null) {
        continue;
      }
      if (nowMs - fileStat.mtimeMs <= STALE_TMP_AGE_MS) {
        continue;
      }
      if (await this.removeFile(filePath)) {
        removedFiles += 1;
        freedBytes += fileStat.size;
      }
    }
    return { removedFiles, freedBytes };
  }

  private async readDirectoryEntries(directoryPath: string, label: string): Promise<Dirent[]> {
    try {
      return await readdir(directoryPath, { withFileTypes: true });
    } catch (error) {
      if (!isNotFoundError(error)) {
        this.logger.debug('cache_directory_unreadable', { directory: label, error });
      }
      return [];
    }
  }

  private async safeStat(filePath: string): Promise<Stats | null> {
    try {
      return await stat(filePath);
    } catch (error) {
      this.logger.debug('cache_stat_failed', { error });
      return null;
    }
  }

  private async removeFile(filePath: string): Promise<boolean> {
    try {
      await rm(filePath, { force: true });
      return true;
    } catch (error) {
      this.logger.debug('cache_remove_failed', { error });
      return false;
    }
  }
}

/**
 * Accepts either the bare 64-hex digest or the `sha256:<64 hex>` cache key produced by
 * `buildQueryIdentity`. Only these two shapes can reach the filesystem; everything else is
 * rejected so no input can inject a path segment.
 */
function toDiskKey(key: string): string | null {
  if (DISK_KEY_PATTERN.test(key)) {
    return key;
  }
  const match = PREFIXED_DISK_KEY_PATTERN.exec(key);
  return match?.[1] ?? null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isEnvelopeFor(
  value: unknown,
  resource: CacheResource,
  diskKey: string,
  envelopeVersion: number,
): value is DiskCacheEnvelope<unknown> {
  if (!isRecord(value)) {
    return false;
  }
  if (value.version !== envelopeVersion) {
    return false;
  }
  if (value.resource !== resource) {
    return false;
  }
  if (value.queryHash !== `${QUERY_HASH_PREFIX}${diskKey}`) {
    return false;
  }
  return isRecord(value.payload);
}

function isNotFoundError(error: unknown): boolean {
  return isRecord(error) && error.code === 'ENOENT';
}
