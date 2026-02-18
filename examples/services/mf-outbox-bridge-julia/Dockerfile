FROM julia:1.12-bookworm

RUN apt-get update \
  && apt-get install -y --no-install-recommends kafkacat ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Project.toml Manifest.toml ./
RUN julia --project=. -e 'using Pkg; Pkg.instantiate()'
COPY src ./src

CMD ["julia", "--project=.", "src/main.jl"]
