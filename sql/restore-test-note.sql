-- 공식 SQL 편집기에서 별도로 검토·적용할 함수입니다. 이 파일은 자동 실행하지 않습니다.
-- 기존 자료·정책·감사 테이블을 삭제하거나 갱신하지 않습니다.
create or replace function public.restore_test_note(
  target_id uuid, target_owner uuid, saved_title text, saved_content text, saved_hash text
) returns table(id uuid, owner_id uuid, content_sha256 text)
language plpgsql security invoker set search_path = '' as $$
declare
  restored public.learning_notes%rowtype;
begin
  if target_id is null or target_owner is null or saved_title is null
     or length(btrim(saved_title)) = 0 or length(saved_title) > 200
     or saved_content is null or length(saved_content) > 20000
     or saved_hash is null or saved_hash !~ '^[a-f0-9]{64}$'
     or encode(sha256(convert_to(saved_content, 'UTF8')), 'hex') <> saved_hash then
    raise exception 'invalid_restore';
  end if;
  insert into public.learning_notes as existing (id, owner_id, title, content)
    values (target_id, target_owner, saved_title, saved_content)
    on conflict on constraint learning_notes_pkey do update
      set title = excluded.title, content = excluded.content
      where existing.owner_id = target_owner
    returning existing.* into restored;
  if not found then return; end if;
  if restored.id is distinct from target_id or restored.owner_id is distinct from target_owner
     or encode(sha256(convert_to(restored.content, 'UTF8')), 'hex') is distinct from saved_hash then
    raise exception 'restore_verification_failed';
  end if;
  return query select restored.id, restored.owner_id,
    encode(sha256(convert_to(restored.content, 'UTF8')), 'hex');
end;
$$;
revoke all on function public.restore_test_note(uuid, uuid, text, text, text) from public, anon, authenticated;
grant execute on function public.restore_test_note(uuid, uuid, text, text, text) to service_role;
