FROM julia:1.12-bookworm

WORKDIR /app
COPY Project.toml Manifest.toml ./
RUN julia --project=. -e 'using Pkg; Pkg.instantiate()'
COPY src ./src

EXPOSE 8080
CMD ["julia", "--project=.", "src/main.jl"]
