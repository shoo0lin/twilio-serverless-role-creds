/**
 * Twilio Serverless Function: send one trial SMS.
 *
 * This exists because the received message is the refutation of the "spam from
 * Twilio's infrastructure" claim: every trial message is prefixed by Twilio and
 * can only be sent to a number verified on the same account.
 *
 * `to` must be a number you have already verified on your own trial account.
 * There is no bulk mode, no number list and no retry loop here on purpose.
 */
exports.handler = function (context, event, callback) {
  const to = event && event.to;
  const from = event && event.from;

  if (!to || !from) {
    return callback(null, {
      error: "pass ?from=<your trial number>&to=<a number verified on this account>",
    });
  }

  const client = context.getTwilioClient();

  client.messages
    .create({
      from: from,
      to: to,
      body:
        (event && event.body) ||
        "BB-REPRO: sent from a trial account over Twilio Serverless.",
    })
    .then(function (m) {
      return callback(null, {
        sid: String(m.sid).slice(0, 10) + "…",
        status: m.status,
        from: m.from,
        to: m.to,
        note: "queued is not delivered; check the handset before claiming delivery",
      });
    })
    .catch(function (e) {
      return callback(null, { error: e.message });
    });
};
