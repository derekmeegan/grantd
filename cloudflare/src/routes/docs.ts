/**
 * The API is its own documentation.
 *
 * A visiting agent arrives with nothing but a URL. Everything it needs must
 * be discoverable with curl. These endpoints return plain text that describes
 * the exact requests to make.
 */

export function docsMarkdown(origin: string): string {
  return `# grantd

Temporary, single-use SSH access for agents.

This service is a **router**. It never holds an SSH CA private key, a host
identity private key, a grant secret, or a visiting agent's SSH private key.
Access is authorized by an HMAC keyed with a secret that only travels in a URL
fragment, from the grant's owner to its recipient, out of band.

Protocol version: 1. Canonical encoding, message schemas and error codes are
specified in \`protocol/v1.md\` in the source repository.

## If you were given a capability URL

    https://…/g/<host_id>/<grant_id>#<secret>

Fetch the path part for instructions:

    curl ${origin}/g/<host_id>/<grant_id>

Keep the fragment — everything after \`#\` — on your own machine. It is the
capability. This service cannot see it, cannot recover it, and cannot help you
if you paste it somewhere public.

## Endpoints

    GET    /                                             this document
    GET    /health

    POST   /v1/agent-challenges                          start registration
    POST   /v1/agents                                    register an agent identity
    GET    /v1/agents/:agent_id

    PUT    /v1/hosts/:host_id                            register a host (host-signed)
    GET    /v1/hosts/:host_id
    GET    /v1/hosts/:host_id/connect                    rendezvous WebSocket (host only)
    PUT    /v1/hosts/:host_id/grants/:grant_id           publish signed grant metadata
    GET    /v1/hosts/:host_id/grants/:grant_id
    POST   /v1/hosts/:host_id/grants/:grant_id/redeem    redeem a capability

    GET    /g/:host_id/:grant_id                         redemption instructions
    GET    /install                                      host installer
    GET    /releases/…                                   signed release artifacts

## Registering an agent identity

Agent registration is self-service and requires no account, no email and no API
key. Generate an Ed25519 keypair; your \`agent_id\` is
\`"a_" + base32(sha256(public_key)[0:20])\` using the lowercase RFC 4648
alphabet without padding.

    curl -sX POST ${origin}/v1/agent-challenges

You receive a proof-of-work prefix and a difficulty in bits. Find a nonce such
that \`sha256(prefix_bytes || utf8(nonce))\` has at least that many leading zero
bits, then sign the registration message with your identity key.

Registration is required to redeem, and is an abuse control rather than a
security boundary: it makes reaching a machine cost a second of CPU. It grants
nothing by itself — authority comes only from a capability secret.

## Error codes

Errors are \`{"error":{"code":"…","message":"…"}}\`. Codes include
\`BAD_PROOF\`, \`GRANT_ALREADY_REDEEMED\`, \`GRANT_EXPIRED\`, \`HOST_OFFLINE\`,
\`HOST_TIMEOUT\`, \`RATE_LIMITED\`. Branch on \`code\`, not on prose.
`;
}

export function grantInstructions(origin: string, hostId: string, grantId: string): string {
  return `grantd SSH grant

Host:  ${hostId}
Grant: ${grantId}

This page never receives the capability secret. It is the part of your URL after
the '#', and browsers and HTTP clients do not transmit fragments. Keep it local.

Redeem it like this.

1. Have an agent identity.

   Generate an Ed25519 keypair if you do not have one. Your agent_id is
   "a_" + base32(sha256(public_key)[0:20]), lowercase RFC 4648, no padding.
   Register it:

     curl -sX POST ${origin}/v1/agent-challenges

   Solve the returned proof of work, then POST the signed registration to
   ${origin}/v1/agents. Registration is required to redeem.

2. Generate a throwaway SSH key. It must be ed25519, and it must never leave
   your machine.

     ssh-keygen -t ed25519 -N '' -C '' -f ./grantd-key

3. Build the redemption payload. Field order matters for the canonical
   encoding, but in JSON it is just an object:

     {
       "version": 1,
       "host_id": "${hostId}",
       "grant_id": "${grantId}",
       "agent_id": "<your agent id>",
       "agent_public_key": "<base64url of your 32-byte identity public key>",
       "ssh_public_key": "ssh-ed25519 AAAA...",   // exactly two fields, no comment
       "timestamp": <unix seconds>,
       "nonce": "<base64url of 16 random bytes>"
     }

   The ssh_public_key string is covered by the proof below, so submit it byte
   for byte as you will use it.

4. Compute two things over the canonical encoding of that payload
   (see protocol/v1.md for the exact bytes):

     agent_signature = Ed25519(agent_key, CBE("grantd/v1/redemption-agent-sig", payload))
     proof           = HMAC-SHA256(secret, CBE("grantd/v1/redemption-proof", payload))

   where 'secret' is the 32 bytes your URL fragment base64url-decodes to.
   Do not send the secret. The proof is what authorizes issuance, and it is
   verified on the customer's own machine.

5. POST it:

     curl -sX POST ${origin}/v1/hosts/${hostId}/grants/${grantId}/redeem \\
       -H 'content-type: application/json' \\
       -d @redemption.json

   On success you receive hostname, port, user, and a certificate.

6. Do not trust that response on its own. This service is not trusted.
   GET ${origin}/v1/hosts/${hostId} returns the host's signed registration
   under "registration" and "signature". Make sure that the host id derives
   from registration.identity_public_key, that the signature verifies over
   CBE("grantd/v1/host-register", registration), and that hostname, port
   and user in the response equal the signed values. Make sure that the
   certificate was signed by registration.ssh_ca_public_key, is for your
   key, and names only that user. protocol/v1.md section 7.1 lists the exact
   steps.

7. Save the certificate next to your key and connect. Pass the user and the
   host as separate arguments. Never build "user@host" from untrusted text.

     printf '%s\\n' "$certificate" > ./grantd-key-cert.pub
     ssh -i ./grantd-key -o CertificateFile=./grantd-key-cert.pub \\
       -l "$user" -p "$port" -- "$hostname"

If you would rather not implement this yourself, redeem.sh does the whole
flow, including every check above, with curl, openssl and ssh-keygen:

  curl -sO ${origin}/redeem.sh
  GRANTD_CAPABILITY='<the full URL, including #secret>' sh redeem.sh

Fetching redeem.sh from here means trusting this service to deliver that
script. The same script is in the grantd repository under install/redeem.sh.

It needs OpenSSL 3.x. macOS ships LibreSSL as 'openssl', which cannot do
Ed25519 at all; the script looks for a capable binary and tells you if it
cannot find one.

Notes.

  The grant is single-use, with no retry path. The first agent to present a
  valid proof wins; everyone else gets GRANT_ALREADY_REDEEMED, and resubmitting
  your own request is refused as a replayed nonce. If you lose the response, ask
  for another URL — grants are free to mint.

  The certificate expires when the grant does. There is no renewal.

  If you get HOST_OFFLINE, the machine is not currently connected. The grant is
  still valid until it expires; try again.
`;
}
