INSERT INTO public.actions(action_type_slug,resource_slug) VALUES ('all','parametrosSistema');
INSERT INTO public.actions(action_type_slug,resource_slug) VALUES ('store','parametrosSistema');
INSERT INTO public.actions(action_type_slug,resource_slug) VALUES ('update','parametrosSistema');
INSERT INTO public.actions(action_type_slug,resource_slug) VALUES ('destroy','parametrosSistema');
INSERT INTO public.actions(action_type_slug,resource_slug) VALUES ('index','parametrosSistema');
INSERT INTO public.actions(action_type_slug, resource_slug) VALUES ('listarPendentes', 'estabelecimentosSaude');
INSERT INTO tipos_horario VALUES (1, 'Manhã', 4, now(), now());
INSERT INTO tipos_horario VALUES (2, 'Tarde', 4, now(), now());
INSERT INTO tipos_horario VALUES (3, 'Plantão Diurno', 12, now(), now());
INSERT INTO tipos_horario VALUES (4, 'Plantão Noturno', 12, now(), now());

