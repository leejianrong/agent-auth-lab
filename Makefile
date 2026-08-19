.PHONY: lab00-setup lab00-test lab00-run docs-serve docs-build generate-starters check-starters

lab00-setup:
	cd labs/lab-00-sessions-cookies/starter/backend && \
		uv venv .venv --python 3.12 && \
		uv pip install -r requirements.txt --python .venv/bin/python
	cd labs/lab-00-sessions-cookies/starter/frontend && npm install

lab00-test:
	cd labs/lab-00-sessions-cookies/solution/backend && \
		uv venv .venv --python 3.12 --allow-existing && \
		uv pip install -r requirements.txt --python .venv/bin/python && \
		.venv/bin/pytest tests/ -v

lab00-run:
	@echo "Starting backend on :8000 and frontend on :5173 (Ctrl+C stops both)"
	cd labs/lab-00-sessions-cookies/starter/backend && .venv/bin/uvicorn app.main:app --reload & \
	cd labs/lab-00-sessions-cookies/starter/frontend && npm run dev

docs-serve:
	uv venv .docs-venv --python 3.12 --allow-existing && \
		uv pip install zensical --python .docs-venv/bin/python && \
		.docs-venv/bin/zensical serve

docs-build:
	uv venv .docs-venv --python 3.12 --allow-existing && \
		uv pip install zensical --python .docs-venv/bin/python && \
		.docs-venv/bin/zensical build --clean --strict

generate-starters:
	for lab in labs/*/; do python3 scripts/generate_starter.py "$${lab%/}"; done

check-starters:
	for lab in labs/*/; do python3 scripts/generate_starter.py --check "$${lab%/}"; done
