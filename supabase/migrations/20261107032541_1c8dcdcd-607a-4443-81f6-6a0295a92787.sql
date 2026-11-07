CREATE TABLE public.app_records (
  table_name text NOT NULL,
  id text NOT NULL,
  data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (table_name, id)
);
CREATE INDEX app_records_list_idx ON public.app_records (table_name, created_at, id);
GRANT ALL ON public.app_records TO service_role;
ALTER TABLE public.app_records ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.app_transact(ops jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  op jsonb; item jsonb; out jsonb := '[]'::jsonb; res jsonb; rid text; cur jsonb; cond jsonb; k text;
BEGIN
  FOR op IN SELECT * FROM jsonb_array_elements(ops) LOOP
    res := '[]'::jsonb;
    IF op->>'op' = 'add' THEN
      FOR item IN SELECT * FROM jsonb_array_elements(op->'items') LOOP
        rid := coalesce(item->>'id', replace(gen_random_uuid()::text,'-',''));
        BEGIN
          INSERT INTO app_records(table_name,id,data) VALUES (op->>'table', rid, item - 'id');
        EXCEPTION WHEN unique_violation THEN
          RAISE EXCEPTION 'AppDatabaseConflict';
        END;
        res := res || to_jsonb(rid);
      END LOOP;
    ELSIF op->>'op' = 'update' THEN
      FOR item IN SELECT * FROM jsonb_array_elements(op->'items') LOOP
        rid := item->>'id';
        SELECT data INTO cur FROM app_records WHERE table_name = op->>'table' AND id = rid FOR UPDATE;
        IF cur IS NULL THEN
          IF item ? 'if' THEN RAISE EXCEPTION 'AppDatabaseConditionFailed'; END IF;
          res := res || 'false'::jsonb; CONTINUE;
        END IF;
        cond := item->'if';
        IF cond IS NOT NULL AND jsonb_typeof(cond) = 'object' THEN
          FOR k IN SELECT jsonb_object_keys(cond) LOOP
            IF (cur->k) IS DISTINCT FROM (cond->k) AND NOT ((cur->k) IS NULL AND (cond->k) = 'null'::jsonb) THEN
              RAISE EXCEPTION 'AppDatabaseConditionFailed';
            END IF;
          END LOOP;
        END IF;
        UPDATE app_records SET data = cur || ((item->'record') - 'id'), updated_at = clock_timestamp()
          WHERE table_name = op->>'table' AND id = rid;
        res := res || 'true'::jsonb;
      END LOOP;
    ELSIF op->>'op' = 'delete' THEN
      FOR item IN SELECT * FROM jsonb_array_elements(op->'items') LOOP
        DELETE FROM app_records WHERE table_name = op->>'table' AND id = (item #>> '{}');
        res := res || to_jsonb(FOUND);
      END LOOP;
    END IF;
    out := out || jsonb_build_array(res);
  END LOOP;
  RETURN out;
END $$;
REVOKE ALL ON FUNCTION public.app_transact(jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.app_transact(jsonb) TO service_role;