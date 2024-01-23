create table
    "group_invites" (
        "id" uuid not null default uuid_generate_v4 (),
        "group_id" uuid not null,
        "role" text not null,
        "invited_by" uuid not null,
        "created_at" timestamp with time zone not null default now(),
        "user_id" uuid,
        "accepted_at" timestamp with time zone
    );

CREATE UNIQUE INDEX group_invites_pkey ON group_invites USING btree (id);

alter table "group_invites"
add constraint "group_invites_pkey" PRIMARY KEY using index "group_invites_pkey";

alter table "group_invites"
add constraint "group_invites_invited_by_fkey" FOREIGN KEY ("invited_by") REFERENCES auth.users (id) not valid;

alter table "group_invites" validate constraint "group_invites_invited_by_fkey";

alter table "group_invites"
add constraint "group_invites_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES groups (id) not valid;

alter table "group_invites" validate constraint "group_invites_group_id_fkey";

alter table "group_invites"
add constraint "group_invites_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES auth.users (id) not valid;

alter table "group_invites" validate constraint "group_invites_user_id_fkey";

alter table "group_invites" enable row level security;

CREATE POLICY "Prevent all CRUD" ON "group_invites" AS PERMISSIVE FOR ALL TO public USING (false)
WITH
    CHECK (false);

alter table "group_invites" enable row level security;