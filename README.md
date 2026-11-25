## Build and test

```sh
uv sync --locked
uv run --locked pytest
uv run --locked rain --help
uv run --locked rain web --help
uv build
```

## Deploy on Slurm 

Use the automated deploy script [`deploy/deploy.sh`](deploy/deploy.sh):

```sh
# Or deploy to a remote Slurm node over SSH:
./deploy/deploy.sh <user@slurm-host>
```
