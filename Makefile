DIAGRAMS := docs/diagrams/IQMComponents.puml docs/diagrams/MonitorSequence.puml docs/diagrams/AnalyzeOnly.puml docs/diagrams/ViewerFlow.puml docs/diagrams/Deployment.puml
OUTDIR := docs/images

.PHONY: diagrams
diagrams: $(DIAGRAMS)
		@mkdir -p $(OUTDIR)
		@ret=0; \
		for f in $(DIAGRAMS); do \
			base=$$(basename $$f .puml); \
			echo "Rendering $$f -> $(OUTDIR)/$$base.png"; \
			if command -v plantuml >/dev/null 2>&1; then \
				plantuml -tpng "$$f" -o "$(OUTDIR)" || ret=1; \
			elif command -v docker >/dev/null 2>&1; then \
				docker run --rm -v "$(PWD)":/ws -w /ws plantuml/plantuml -tpng "$$f" -o "$(OUTDIR)" || ret=1; \
			else \
				echo "Error: PlantUML not found (local or docker). Cannot render $$f"; \
				ret=1; \
			fi; \
		done; \
		exit $$ret
