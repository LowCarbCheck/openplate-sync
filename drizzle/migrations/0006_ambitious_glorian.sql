CREATE TABLE "signup_invites" (
	"id" serial PRIMARY KEY NOT NULL,
	"token_hash" text NOT NULL,
	"note" text,
	"expires_at" timestamp NOT NULL,
	"redeemed_at" timestamp,
	"redeemed_account_id" integer,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "signup_invites" ADD CONSTRAINT "signup_invites_redeemed_account_id_accounts_id_fk" FOREIGN KEY ("redeemed_account_id") REFERENCES "public"."accounts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "signup_invites_hash_idx" ON "signup_invites" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "signup_invites_created_idx" ON "signup_invites" USING btree ("created_at");