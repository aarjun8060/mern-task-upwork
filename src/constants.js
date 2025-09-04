export const DB_NAME = "merntaskDB";

export const USER_TYPES = {
  User: 1,
};

export const PLATFORM = {
  USERAPP: 1,
};

export let LOGIN_ACCESS = {
  [USER_TYPES.User]: [PLATFORM.USERAPP],
};

// Auth Constants
export const MAX_LOGIN_RETRY_LIMIT = 5;
export const LOGIN_REACTIVE_TIME = 2;

export const JWT = {
  USERAPP_SECRET: "myjwtuserappsecret",
  EXPIRES_IN: 10000,
};
