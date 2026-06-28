-- Reset all saved cartons and pallet sets for every account.
-- Run this in Cloudflare: Workers & Pages -> D1 -> pallet3d-db -> Console
-- (or: npx wrangler d1 execute pallet3d-db --remote --file=wipe_user_data.sql)
-- This does NOT touch user accounts, only their saved packages and pallets.

DELETE FROM packages;
DELETE FROM saved_pallets;
