export type CpeTitle = {
  title: string;
  lang: string;
};

export type CpeReference = {
  ref: string;
  type: string | null;
};

export type CpeDeprecatedBy = {
  cpeName: string;
  cpeNameId: string;
};

export type CpeRecord = {
  cpeNameId: string;
  cpeName: string;
  deprecated: boolean;
  created: string;
  lastModified: string;
  titles: CpeTitle[];
  refs: CpeReference[];
  /** CPE names that deprecate this entry. */
  deprecatedBy: CpeDeprecatedBy[];
  /** CPE names this entry deprecates (inverse relation, present on deprecated entries). */
  deprecates: CpeDeprecatedBy[];
};

export type CpeMatchName = {
  cpeName: string;
  cpeNameId: string;
};

export type CpeMatchRecord = {
  matchCriteriaId: string;
  criteria: string;
  status: string;
  created: string;
  lastModified: string;
  cpeLastModified: string | null;
  versionStartIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndIncluding: string | null;
  versionEndExcluding: string | null;
  matches: CpeMatchName[];
};
