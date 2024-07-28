#!/bin/bash
plgo
docker build . -t urtho/pg16algorand
docker push urtho/pg16algorand:latest
