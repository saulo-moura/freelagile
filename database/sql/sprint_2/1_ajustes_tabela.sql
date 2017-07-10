DELETE FROM public.setores;
ALTER TABLE "vagas" drop column "data_inicio";
alter table "vagas" drop column "data_fim";
alter table "vagas" add column "data_inicio" timestamp(0) with time zone not null, add column "data_fim" timestamp(0) with time zone not null;
alter table "setores" drop constraint "setores_tipo_id_foreign";
alter table "setores" drop column "tipo_id";
create table "setores_tipos_estabelecimento_saude" ("id" serial primary key not null, "setor_id" integer not null, "tipo_estabelecimento_saude_id" integer not null, "created_at" timestamp(0) with time zone not null, "updated_at" timestamp(0) with time zone not null);
ALTER TABLE public.setores_tipos_estabelecimento_saude OWNER TO usr_sesab_sgeo;
alter table "setores_tipos_estabelecimento_saude" add constraint "setores_tipos_estabelecimento_saude_setor_id_foreign" foreign key ("setor_id") references "setores" ("id");
alter table "setores_tipos_estabelecimento_saude" add constraint "setores_tipos_estabelecimento_saude_tipo_estabelecimento_saude_id_foreign" foreign key ("tipo_estabelecimento_saude_id") references "tipos_estabelecimento_saude" ("id");



