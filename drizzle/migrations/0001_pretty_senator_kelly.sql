CREATE TABLE "sync_shares" (
	"id" serial PRIMARY KEY NOT NULL,
	"account_id" integer NOT NULL,
	"grantee_account_id" integer NOT NULL,
	"wrapped_dek" "bytea" NOT NULL,
	"recipient_key_fingerprint" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "sync_shares_not_self" CHECK ("sync_shares"."account_id" <> "sync_shares"."grantee_account_id")
);
--> statement-breakpoint
ALTER TABLE "sync_shares" ADD CONSTRAINT "sync_shares_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sync_shares" ADD CONSTRAINT "sync_shares_grantee_account_id_accounts_id_fk" FOREIGN KEY ("grantee_account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "sync_shares_pair_idx" ON "sync_shares" USING btree ("account_id","grantee_account_id");--> statement-breakpoint
CREATE INDEX "sync_shares_grantee_idx" ON "sync_shares" USING btree ("grantee_account_id");