const DEFAULT_ARTIFACT_DIR = joinpath(first(DEPOT_PATH), "artifacts", "rulia")

mutable struct HashingWriter <: IO
    io::IO
    ctx::SHA.SHA256_CTX
end

Base.isopen(writer::HashingWriter) = isopen(writer.io)
Base.close(writer::HashingWriter) = close(writer.io)
Base.flush(writer::HashingWriter) = flush(writer.io)

function Base.write(writer::HashingWriter, data::StridedVector{UInt8})
    SHA.update!(writer.ctx, data)
    return write(writer.io, data)
end

function Base.write(writer::HashingWriter, data::AbstractVector{UInt8})
    buffer = Vector{UInt8}(data)
    SHA.update!(writer.ctx, buffer)
    return write(writer.io, buffer)
end

function platform_target()
    if Sys.islinux() && Sys.ARCH === :x86_64
        return "x86_64-unknown-linux-gnu"
    elseif Sys.isapple() && (Sys.ARCH === :aarch64 || Sys.ARCH === :arm64)
        return "aarch64-apple-darwin"
    elseif Sys.isapple() && Sys.ARCH === :x86_64
        return "x86_64-apple-darwin"
    elseif Sys.iswindows() && Sys.ARCH === :x86_64
        return "x86_64-pc-windows-msvc"
    end
    error("unsupported platform: ", Sys.KERNEL, " / ", Sys.ARCH)
end

function lib_filename()
    if Sys.iswindows()
        return "rulia.dll"
    elseif Sys.isapple()
        return "librulia.dylib"
    else
        return "librulia.so"
    end
end

function resolve_relative_url(manifest_url::String, rel::String)
    if startswith(manifest_url, "file://")
        base_path = replace(manifest_url, r"^file://" => "")
        base_dir = dirname(base_path)
        return "file://" * joinpath(base_dir, rel)
    end

    if endswith(manifest_url, "/")
        return manifest_url * rel
    end

    slash = findlast(==('/'), manifest_url)
    if slash === nothing
        return manifest_url * "/" * rel
    end
    return manifest_url[1:slash] * rel
end

function resolve_artifact_url(manifest_url::String, artifact::Dict{String, Any})
    if haskey(artifact, "url")
        url = String(artifact["url"])
        if startswith(url, "http://") || startswith(url, "https://") || startswith(url, "file://")
            return url
        end
        return resolve_relative_url(manifest_url, url)
    end

    if !haskey(artifact, "file")
        error("artifact entry missing url or file field")
    end
    return resolve_relative_url(manifest_url, String(artifact["file"]))
end

function download_text(manifest_url::String)
    if startswith(manifest_url, "file://")
        path = replace(manifest_url, r"^file://" => "")
        return read(path, String)
    end
    path = Downloads.download(manifest_url)
    return read(path, String)
end

function download_with_sha256(url::String)
    tmp_path, tmp_io = mktemp()
    ctx = SHA.SHA256_CTX()
    writer = HashingWriter(tmp_io, ctx)
    try
        Downloads.download(url, writer)
    finally
        close(writer)
    end
    digest = bytes2hex(SHA.digest!(ctx))
    return tmp_path, digest
end

function extract_tar_gz(tar_path::String, dest::String)
    mkpath(dest)
    open(tar_path, "r") do io
        gz = GzipDecompressorStream(io)
        Tar.extract(gz, dest)
        close(gz)
    end
end

function find_shared_library(artifact_dir::String, target::String)
    name = lib_filename()
    candidate_dirs = [
        joinpath(artifact_dir, target, "lib"),
        joinpath(artifact_dir, "lib"),
    ]
    for dir in candidate_dirs
        path = joinpath(dir, name)
        if isfile(path)
            return path
        end
    end
    error("shared library not found; expected ", name, " under ", candidate_dirs)
end

function install_tools(manifest_url::String, version::String; cache_dir::Union{Nothing, String} = nothing)
    manifest_text = download_text(manifest_url)
    manifest = JSON.parse(manifest_text)

    if !haskey(manifest, "version")
        error("manifest missing version")
    end
    manifest_version = String(manifest["version"])
    if manifest_version != version
        error("manifest version mismatch: expected ", version, " got ", manifest_version)
    end

    target = platform_target()
    artifacts = get(manifest, "artifacts", nothing)
    if artifacts === nothing
        error("manifest missing artifacts")
    end

    selected = nothing
    for artifact in artifacts
        if get(artifact, "target", nothing) == target
            selected = artifact
            break
        end
    end
    selected === nothing && error("no artifact for target ", target)

    artifact_url = resolve_artifact_url(manifest_url, selected)
    expected_sha = lowercase(String(selected["sha256"]))

    artifact_root = cache_dir === nothing ? DEFAULT_ARTIFACT_DIR : abspath(cache_dir)
    target_dir = joinpath(artifact_root, target)

    if !isdir(target_dir)
        mkpath(target_dir)
    end

    tmp_path = nothing
    actual_sha = ""
    try
        tmp_path, actual_sha = download_with_sha256(artifact_url)
        if lowercase(actual_sha) != expected_sha
            error("sha256 mismatch for artifact: expected ", expected_sha, " got ", actual_sha)
        end
        extract_tar_gz(tmp_path, target_dir)
    finally
        if tmp_path !== nothing && isfile(tmp_path)
            rm(tmp_path; force=true)
        end
    end

    lib_path = find_shared_library(artifact_root, target)
    load_library(lib_path)
    return lib_path
end
