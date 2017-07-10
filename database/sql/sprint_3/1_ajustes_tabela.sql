CREATE TABLE "parametros_sistema" ("id" serial primary key not null, "chave" varchar(255) not null, "valor" varchar(255) not null, "descricao" varchar(255) not null, "created_at" timestamp(0) with time zone null, "updated_at" timestamp(0) with time zone null);
ALTER TABLE public.parametros_sistema OWNER TO usr_sesab_sgeo;
CREATE TABLE "tipos_horario" ("id" serial primary key not null, "descricao" varchar(50) not null, "duracao" integer not null, "created_at" timestamp(0) with time zone not null, "updated_at" timestamp(0) with time zone not null);
ALTER TABLE public.tipos_horario OWNER TO usr_sesab_sgeo;
CREATE TABLE "horarios" ("id" serial primary key not null, "vaga_id" integer not null, "qtd_vagas" integer not null, "titulo" varchar(255) not null, "dia_semana" integer not null, "tipo_horario_id" integer not null, "created_at" timestamp(0) with time zone not null, "updated_at" timestamp(0) with time zone not null);
ALTER TABLE public.horarios OWNER TO usr_sesab_sgeo;
ALTER TABLE "users" ADD COLUMN "deleted_at" timestamp(0) WITHOUT TIME ZONE null;
ALTER TABLE "horarios" ADD CONSTRAINT "horarios_vaga_id_foreign" FOREIGN KEY ("vaga_id") REFERENCES "vagas" ("id");
ALTER TABLE "horarios" ADD CONSTRAINT "horarios_tipo_horario_id_foreign" FOREIGN KEY ("tipo_horario_id") REFERENCES "tipos_horario" ("id");
ALTER TABLE "vagas" ADD COLUMN "total_vagas_ano" INTEGER null;

