// A stand-in for `tine hook capture` in tests: answers like the generic
// receiver, echoing the event and its argv, and refuses a "refuse-me" session.
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  const event = JSON.parse(input);
  const ok = event.session !== "refuse-me";
  const answer = ok
    ? { protocol: "opentine-hook/1", ok, event: event.event, argv: process.argv.slice(2) }
    : { protocol: "opentine-hook/1", ok, reason: "refused" };
  process.stdout.write("log line a receiver must not print\n" + JSON.stringify(answer) + "\n");
});
