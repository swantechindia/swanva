.PHONY: migrate upgrade stamp history current

VENV ?= .venv
ALEMBIC ?= $(VENV)/bin/alembic
MSG ?= schema update

migrate:
	$(ALEMBIC) revision --autogenerate -m "$(MSG)"

upgrade:
	$(ALEMBIC) upgrade head

stamp:
	$(ALEMBIC) stamp head

history:
	$(ALEMBIC) history

current:
	$(ALEMBIC) current
