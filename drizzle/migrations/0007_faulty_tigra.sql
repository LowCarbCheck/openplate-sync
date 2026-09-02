ALTER TABLE "accounts" RENAME COLUMN "email" TO "handle";--> statement-breakpoint
DROP INDEX "accounts_email_idx";--> statement-breakpoint
CREATE UNIQUE INDEX "accounts_handle_idx" ON "accounts" USING btree ("handle");--> statement-breakpoint
ALTER TABLE "accounts" DROP COLUMN "email_verified_at";