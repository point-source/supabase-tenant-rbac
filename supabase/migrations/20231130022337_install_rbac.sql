select
    dbdev.install ('pointsource-supabase_rbac');

create extension if not exists "pointsource-supabase_rbac"
with
    schema "public" version '0.0.1';