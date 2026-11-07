# Strip the TAA runtime out of a taa-env image, leaving the Python environment.
#
# The delivery package boots TAA from the initrd; an image that also starts its
# own copy of TAA gives the guest two. Everything TAA-specific is removed here
# and the entrypoint is reset, so the result is a plain environment image.
#
# Build:
#   docker build -f Dockerfile \
#     --build-arg BASE=172.16.10.178:31313/taa-env:slim-v2-20261022 \
#     -t 172.16.10.178:31313/taa-env:v1-train-infer .
ARG BASE
FROM ${BASE}

# The working directory has to be moved off /root/taa *before* the tree is
# removed: docker recreates a missing WORKDIR during the build, so deleting
# first leaves an empty /root/taa behind.
WORKDIR /
RUN rm -rf /root/taa /opt/taa /root/.bash_history

# The base sets its entrypoint to the TAA supervisor, which no longer exists.
ENTRYPOINT []

# Numeric, not the name "root": containerd resolves a user *name* against
# /etc/passwd on the host-side snapshot. Under the nydus snapshotter in
# guest-pull mode that snapshot carries metadata only, so the lookup fails with
# "mount callback failed ... /etc/passwd: no such file or directory" and the Pod
# never reaches the guest. A numeric UID needs no lookup.
USER 0
CMD ["/bin/bash"]
