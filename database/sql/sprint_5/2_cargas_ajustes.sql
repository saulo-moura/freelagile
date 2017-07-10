UPDATE public.areas SET nome = UPPER(nome);
UPDATE public.cursos SET nome = UPPER(nome);
UPDATE public.modalidades SET nome = UPPER(nome);
UPDATE public.setores SET nome = UPPER(nome);
UPDATE public.tipos_estabelecimento_saude SET nome = UPPER(nome);
INSERT INTO public.nucleos_regionais(id, nome, created_at, updated_at) VALUES (11, 'Sul', now(), now());
SELECT pg_catalog.setval('nucleos_regionais_id_seq', 11, true);
UPDATE municipios SET nucleo_regional_id = 11 WHERE id >= 147 AND id <= 213;