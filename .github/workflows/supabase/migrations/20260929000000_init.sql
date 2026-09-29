-- Notificaciones (comentarios, tickets nuevos, invitaciones)
create table if not exists notifications(id uuid primary key default gen_random_uuid(),user_id uuid not null references auth.users(id) on delete cascade,ticket_id uuid references tickets(id) on delete cascade,ticket_n bigint,ticket_title text,kind text not null,by_name text,body text,read boolean not null default false,created_at timestamptz default now());
create index if not exists n_user on notifications(user_id,read,created_at desc);
alter table notifications enable row level security;
drop policy if exists n_sel on notifications;drop policy if exists n_upd on notifications;drop policy if exists n_del on notifications;
create policy n_sel on notifications for select using(user_id=auth.uid());
create policy n_upd on notifications for update using(user_id=auth.uid()) with check(user_id=auth.uid());
create policy n_del on notifications for delete using(user_id=auth.uid());
do $$ begin alter publication supabase_realtime add table notifications; exception when duplicate_object then null; end $$;

-- Comentario nuevo: avisa a PM, invitados y quienes ya comentaron (menos al autor)
create or replace function notify_comment() returns trigger language plpgsql security definer set search_path=public as $$
declare t tickets%rowtype;u uuid;
begin
 select * into t from tickets where id=new.ticket_id;
 for u in select distinct x from(select t.pm x union select unnest(t.assistants) union select author from ticket_updates where ticket_id=new.ticket_id)a where x is not null and x<>new.author loop
  insert into notifications(user_id,ticket_id,ticket_n,ticket_title,kind,by_name,body) values(u,t.id,t.n,t.data->>'title','comment',new.author_name,left(coalesce(nullif(new.done,''),new.next),140));
 end loop;return new;
end $$;
drop trigger if exists u_notify on ticket_updates;
create trigger u_notify after insert on ticket_updates for each row execute function notify_comment();

-- Ticket nuevo (avisa a PM e invitados) o nuevas invitaciones / cambio de PM
create or replace function notify_ticket() returns trigger language plpgsql security definer set search_path=public as $$
declare u uuid;nm text;
begin
 select name into nm from profiles where id=auth.uid();
 if tg_op='INSERT' then
  for u in select distinct x from(select new.pm x union select unnest(new.assistants))a where x is not null and x is distinct from auth.uid() loop
   insert into notifications(user_id,ticket_id,ticket_n,ticket_title,kind,by_name,body) values(u,new.id,new.n,new.data->>'title','ticket_new',nm,'Nuevo ticket asignado');
  end loop;
 else
  for u in select distinct x from(select case when new.pm is distinct from old.pm then new.pm end x union select unnest(array(select unnest(new.assistants) except select unnest(old.assistants))))a where x is not null and x is distinct from auth.uid() loop
   insert into notifications(user_id,ticket_id,ticket_n,ticket_title,kind,by_name,body) values(u,new.id,new.n,new.data->>'title','invited',nm,'Fuiste agregado al ticket');
  end loop;
 end if;return new;
end $$;
drop trigger if exists t_notify on tickets;
create trigger t_notify after insert or update of pm,assistants on tickets for each row execute function notify_ticket();

create or replace function schema_version() returns int language sql immutable as $$select 3$$;
