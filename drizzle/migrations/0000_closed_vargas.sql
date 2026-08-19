CREATE TABLE "account_tokens" (
	"id" serial PRIMARY KEY NOT NULL,
	"account_id" integer NOT NULL,
	"kind" text NOT NULL,
	"token_hash" text NOT NULL,
	"family_id" text,
	"expires_at" timestamp NOT NULL,
	"revoked_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "accounts" (
	"id" serial PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"display_name" text,
	"verifier" text NOT NULL,
	"kdf_descriptor" jsonb NOT NULL,
	"email_verified_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sync_blobs" (
	"id" serial PRIMARY KEY NOT NULL,
	"account_id" integer NOT NULL,
	"blob_version" integer NOT NULL,
	"envelope_version" integer NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"size_bytes" integer NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sync_key_records" (
	"id" serial PRIMARY KEY NOT NULL,
	"account_id" integer NOT NULL,
	"kind" text NOT NULL,
	"kdf_descriptor" jsonb,
	"wrapped_dek" "bytea" NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "account_tokens" ADD CONSTRAINT "account_tokens_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sync_blobs" ADD CONSTRAINT "sync_blobs_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sync_key_records" ADD CONSTRAINT "sync_key_records_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "account_tokens_hash_idx" ON "account_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "account_tokens_account_kind_idx" ON "account_tokens" USING btree ("account_id","kind");--> statement-breakpoint
CREATE INDEX "account_tokens_family_idx" ON "account_tokens" USING btree ("family_id");--> statement-breakpoint
CREATE INDEX "account_tokens_expires_idx" ON "account_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "accounts_email_idx" ON "accounts" USING btree ("email");--> statement-breakpoint
CREATE UNIQUE INDEX "sync_blobs_account_version_idx" ON "sync_blobs" USING btree ("account_id","blob_version");--> statement-breakpoint
CREATE INDEX "sync_blobs_account_idx" ON "sync_blobs" USING btree ("account_id");--> statement-breakpoint
CREATE UNIQUE INDEX "sync_key_records_account_kind_idx" ON "sync_key_records" USING btree ("account_id","kind");