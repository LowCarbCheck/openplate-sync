CREATE TABLE "research_contributions" (
	"id" serial PRIMARY KEY NOT NULL,
	"contributor_account_id" integer NOT NULL,
	"study_account_id" integer NOT NULL,
	"pseudonym" text NOT NULL,
	"schema_tier" text NOT NULL,
	"body" "bytea" NOT NULL,
	"contribution_version" integer NOT NULL,
	"created_at" timestamp (3) DEFAULT now() NOT NULL,
	"updated_at" timestamp (3) DEFAULT now() NOT NULL,
	CONSTRAINT "research_contributions_not_self" CHECK ("research_contributions"."contributor_account_id" <> "research_contributions"."study_account_id")
);
--> statement-breakpoint
CREATE TABLE "research_withdrawals" (
	"id" serial PRIMARY KEY NOT NULL,
	"study_account_id" integer NOT NULL,
	"pseudonym" text NOT NULL,
	"withdrawn_at" timestamp (3) DEFAULT now() NOT NULL,
	CONSTRAINT "research_withdrawals_pseudonym_present" CHECK (length("research_withdrawals"."pseudonym") > 0)
);
--> statement-breakpoint
ALTER TABLE "research_contributions" ADD CONSTRAINT "research_contributions_contributor_account_id_accounts_id_fk" FOREIGN KEY ("contributor_account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "research_contributions" ADD CONSTRAINT "research_contributions_study_account_id_accounts_id_fk" FOREIGN KEY ("study_account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "research_withdrawals" ADD CONSTRAINT "research_withdrawals_study_account_id_accounts_id_fk" FOREIGN KEY ("study_account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "research_contributions_pair_idx" ON "research_contributions" USING btree ("contributor_account_id","study_account_id");--> statement-breakpoint
CREATE INDEX "research_contributions_study_idx" ON "research_contributions" USING btree ("study_account_id");--> statement-breakpoint
CREATE UNIQUE INDEX "research_withdrawals_pair_idx" ON "research_withdrawals" USING btree ("study_account_id","pseudonym");