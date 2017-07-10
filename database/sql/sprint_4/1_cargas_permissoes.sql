INSERT INTO public.actions(action_type_slug, resource_slug) VALUES ('gerarRelatorio', 'vagas');
INSERT INTO public.actions_dependencies (dependent_action_id, depends_on_action_id)
VALUES (
	(
		SELECT		id
		FROM		public.actions
		WHERE		resource_slug = 'vagas' AND action_type_slug = 'gerarRelatorio'
	),
	(
		SELECT		id
		FROM		public.actions
		WHERE		resource_slug = 'vagas' AND action_type_slug = 'index'
	)
);



