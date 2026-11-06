// Where updates come from, and who may sign them.
//
// UPDATE_KEYS are the Ed25519 public keys (base64, 32 bytes) whose signature an
// update must carry. `npm run release-key -w @silo/desktop` creates a key pair and
// writes its public half here. With no key listed, the app never installs updates.
//
// UPDATE_FEED is a GitHub releases page. The app reads
// `<feed>/latest/download/silo-update.json` and the files from
// `<feed>/download/v<version>/<file>`. Both must be readable without signing in,
// so the repository (or a mirror of its releases) has to be public.

export const UPDATE_FEED = 'https://github.com/MichaelDamiano/silo/releases';

export const UPDATE_KEYS: string[] = [
  'VlphmI+VkPLV5kSQ0Z82wLZ2nQ32v7x04DjXpvfOFJI=',
];
