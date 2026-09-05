TEX = audit-research-ieee.tex
PDF = audit-research-ieee.pdf

.PHONY: all clean

all: $(PDF)

$(PDF): $(TEX)
	@if command -v xelatex >/dev/null 2>&1; then \
		xelatex -interaction=nonstopmode -halt-on-error $(TEX); \
		xelatex -interaction=nonstopmode -halt-on-error $(TEX); \
	else \
		echo "ERROR: xelatex not found. Install a TeX distribution with IEEEtran and ctex/xeCJK support."; \
		exit 127; \
	fi

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.lof *.lot *.fls *.fdb_latexmk $(PDF)
