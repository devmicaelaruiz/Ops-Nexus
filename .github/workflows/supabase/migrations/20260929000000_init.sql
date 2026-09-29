-- PM Desk v2 · Supabase + RLS. Es idempotente: puedes ejecutarlo completo aunque ya hayas corrido la v1.
create table if not exists profiles(id uuid primary key references auth.users(id) on delete cascade,name text not null,email text,role text not null check(role in('admin','tecnico','asistente')));
create table if not exists config(id int primary key check(id=1),data jsonb not null default '{}');
create table if not exists tickets(id uuid primary key default gen_random_uuid(),n bigint generated always as identity,pm uuid,assistants uuid[] not null default '{}',data jsonb not null default '{}',created_at timestamptz default now());
alter table tickets add column if not exists last_update_at timestamptz;
create table if not exists ticket_updates(id uuid primary key default gen_random_uuid(),ticket_id uuid not null references tickets(id) on delete cascade,author uuid not null default auth.uid(),author_name text,done text,next text,created_at timestamptz default now());
insert into config values(1,'{}') on conflict do nothing;
alter table profiles enable row level security;alter table config enable row level security;alter table tickets enable row level security;alter table ticket_updates enable row level security;

create or replace function my_role() returns text language sql security definer stable set search_path=public as $$select role from profiles where id=auth.uid()$$;
-- Permiso efectivo: override por usuario > permiso del rol > valor por defecto
create or replace function has_perm(p text) returns boolean language sql security definer stable set search_path=public as $$
 select case when my_role()='admin' then true when my_role() is null then false else coalesce(
  (select (data->'userPerms'->(auth.uid()::text)->>p)::boolean from config where id=1),
  (select (data->'perms'->my_role()->>p)::boolean from config where id=1),
  case my_role() when 'tecnico' then p<>'delete' else p in('edit','status','chat') end) end $$;

drop policy if exists p_sel on profiles;drop policy if exists p_ins on profiles;drop policy if exists p_upd on profiles;drop policy if exists p_del on profiles;
create policy p_sel on profiles for select using(id=auth.uid() or my_role() is not null);
create policy p_ins on profiles for insert with check(my_role()='admin');
create policy p_upd on profiles for update using(my_role()='admin');
create policy p_del on profiles for delete using(my_role()='admin');

drop policy if exists c_sel on config;drop policy if exists c_ins on config;drop policy if exists c_upd on config;
create policy c_sel on config for select using(my_role() is not null);
create policy c_ins on config for insert with check(my_role()='admin');
create policy c_upd on config for update using(my_role()='admin');

drop policy if exists t_sel on tickets;drop policy if exists t_ins on tickets;drop policy if exists t_upd on tickets;drop policy if exists t_del on tickets;
create policy t_sel on tickets for select using(my_role() is not null and(my_role()='admin' or has_perm('viewAll') or pm=auth.uid() or auth.uid()=any(assistants)));
create policy t_ins on tickets for insert with check(my_role() is not null and has_perm('create'));
create policy t_upd on tickets for update using(my_role() is not null and(my_role()='admin' or(has_perm('edit') and(my_role()<>'asistente' or has_perm('viewAll') or auth.uid()=any(assistants)))));
create policy t_del on tickets for delete using(my_role() is not null and has_perm('delete'));

drop policy if exists u_sel on ticket_updates;drop policy if exists u_ins on ticket_updates;drop policy if exists u_del on ticket_updates;
create policy u_sel on ticket_updates for select using(has_perm('chat') and exists(select 1 from tickets t where t.id=ticket_id));
create policy u_ins on ticket_updates for insert with check(has_perm('chat') and author=auth.uid() and exists(select 1 from tickets t where t.id=ticket_id));
create policy u_del on ticket_updates for delete using(my_role()='admin');

create or replace function bump_ticket() returns trigger language plpgsql security definer set search_path=public as $$
begin update tickets set last_update_at=now() where id=new.ticket_id;return new;end $$;
drop trigger if exists u_bump on ticket_updates;
create trigger u_bump after insert on ticket_updates for each row execute function bump_ticket();

-- El asistente solo puede modificar campos marcados "Asistente" (y estado si tiene permiso)
create or replace function guard_ticket() returns trigger language plpgsql security definer set search_path=public as $$
declare k text;c jsonb;
begin
 if my_role()='asistente' then
  if new.pm is distinct from old.pm or new.assistants is distinct from old.assistants then raise exception 'No permitido';end if;
  select data into c from config where id=1;
  for k in select coalesce(n.key,o.key) from jsonb_each(new.data) as n(key,value) full join jsonb_each(old.data) as o(key,value) on n.key=o.key where n.value is distinct from o.value loop
   if not((k='status' and has_perm('status')) or coalesce((c->'fields'->k->>'ast')::boolean,k in('requester','requestedAt','summary','estado'))) then raise exception 'Campo no permitido: %',k;end if;
  end loop;
 end if;return new;
end $$;
drop trigger if exists t_guard on tickets;
create trigger t_guard before update on tickets for each row execute function guard_ticket();

-- Versión del esquema: sube este número (y SCHEMA_REQ en index.html) cuando cambies la base
create or replace function schema_version() returns int language sql immutable as $$select 2$$;
