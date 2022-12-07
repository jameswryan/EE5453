#!/usr/bin/env sh
pandoc JamesRyan.md header.yml --pdf-engine=tectonic -s -t latex | sed 's:\\begin{figure}:\\begin{figure}[H]:' > final.tex && tectonic final.tex
