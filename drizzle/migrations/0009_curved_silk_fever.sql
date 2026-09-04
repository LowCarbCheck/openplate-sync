CREATE TABLE "ai_usage_days" (
	"account_id" integer NOT NULL,
	"day" date NOT NULL,
	"count" integer DEFAULT 0 NOT NULL,
	CONSTRAINT "ai_usage_days_account_id_day_pk" PRIMARY KEY("account_id","day")
);
--> statement-breakpoint
CREATE TABLE "password_resets" (
	"id" serial PRIMARY KEY NOT NULL,
	"account_id" integer NOT NULL,
	"token_hash" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"consumed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "accounts" RENAME COLUMN "handle" TO "email";--> statement-breakpoint
DROP INDEX "accounts_handle_idx";--> statement-breakpoint
ALTER TABLE "accounts" ADD COLUMN "role" text DEFAULT 'member' NOT NULL;--> statement-breakpoint
ALTER TABLE "accounts" ADD COLUMN "daily_ai_limit" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "accounts" ADD COLUMN "suspended_at" timestamp;--> statement-breakpoint
ALTER TABLE "accounts" ADD COLUMN "last_seen_at" timestamp;--> statement-breakpoint
ALTER TABLE "accounts" ADD COLUMN "recovery_code_escrow" "bytea";--> statement-breakpoint
ALTER TABLE "signup_invites" ADD COLUMN "email" text NOT NULL;--> statement-breakpoint
ALTER TABLE "signup_invites" ADD COLUMN "display_name" text;--> statement-breakpoint
ALTER TABLE "signup_invites" ADD COLUMN "role" text DEFAULT 'member' NOT NULL;--> statement-breakpoint
ALTER TABLE "signup_invites" ADD COLUMN "daily_ai_limit" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "signup_invites" ADD COLUMN "revoked_at" timestamp;--> statement-breakpoint
ALTER TABLE "ai_usage_days" ADD CONSTRAINT "ai_usage_days_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "password_resets" ADD CONSTRAINT "password_resets_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "password_resets_hash_idx" ON "password_resets" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "password_resets_account_idx" ON "password_resets" USING btree ("account_id");--> statement-breakpoint
CREATE UNIQUE INDEX "accounts_email_idx" ON "accounts" USING btree ("email");--> statement-breakpoint
CREATE INDEX "signup_invites_email_idx" ON "signup_invites" USING btree ("email");--> statement-breakpoint
ALTER TABLE "signup_invites" DROP COLUMN "note";