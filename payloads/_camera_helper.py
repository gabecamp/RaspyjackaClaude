"""
Camera source helper for RaspyJack payloads.

Prefers a USB UVC webcam (driven by ffmpeg through V4L2) and falls back to
the CSI camera (rpicam tools) when no USB capture device is present.

Streams produced by start_stream() are raw yuv420p frames of
w * h * 3 // 2 bytes each, the same contract the rpicam-vid "-o -" pipe
used, so existing frame-reading loops keep working unchanged.
"""

import glob
import os
import signal
import subprocess

V4L_SYS = "/sys/class/video4linux"
# Two 90-degree transposes = 180-degree rotation (matches --rotation 180).
ROTATE_VF = "transpose=2,transpose=2"
_FFMPEG_BASE = ["ffmpeg", "-hide_banner", "-loglevel", "error"]


def _video_index(node):
    try:
        return int(os.path.basename(node)[5:])
    except ValueError:
        return 9999


def find_uvc_device():
    """Return /dev/videoN for the first USB video-capture node, or None.

    UVC cameras expose two video nodes; the capture node is index 0.
    """
    for node in sorted(glob.glob(os.path.join(V4L_SYS, "video*")),
                       key=_video_index):
        try:
            with open(os.path.join(node, "index")) as f:
                if f.read().strip() != "0":
                    continue
        except OSError:
            continue
        if "/usb" not in os.path.realpath(os.path.join(node, "device")):
            continue
        dev = "/dev/" + os.path.basename(node)
        if os.path.exists(dev):
            return dev
    return None


def camera_backend():
    """'uvc' when a USB webcam is attached, otherwise 'csi'."""
    return "uvc" if find_uvc_device() else "csi"


def _uvc_vf(w, h, fps, rotate):
    parts = [ROTATE_VF] if rotate else []
    if fps:
        parts.append(f"fps={fps}")
    parts.append(f"scale={w}:{h}")
    return ",".join(parts)


def _rpicam_rot(rotate):
    return ["--rotation", "180"] if rotate else []


def start_stream(w, h, fps=15, rotate=True, pix_fmt="rgb24"):
    """Start a live raw frame stream on stdout (Popen).

    pix_fmt: 'rgb24' for PIL-friendly RGB output, 'yuv420p' for legacy.
    """
    dev = find_uvc_device()
    if dev:
        cmd = _FFMPEG_BASE + ["-f", "v4l2", "-i", dev,
                              "-vf", _uvc_vf(w, h, fps, rotate),
                              "-pix_fmt", pix_fmt, "-f", "rawvideo", "-"]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, bufsize=0)

    # CSI camera: rpicam-vid → ffmpeg for pixel format conversion
    rpicam_cmd = (["rpicam-vid", "--width", str(w), "--height", str(h),
                   "--framerate", str(fps), "--codec", "yuv420"]
                  + _rpicam_rot(rotate)
                  + ["-t", "0", "--nopreview", "-o", "-"])
    if pix_fmt == "yuv420p":
        return subprocess.Popen(rpicam_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, bufsize=0)
    rpicam = subprocess.Popen(rpicam_cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, bufsize=0)
    ff_cmd = _FFMPEG_BASE + ["-f", "rawvideo", "-pix_fmt", "yuv420p",
                             "-video_size", f"{w}x{h}",
                             "-framerate", str(fps), "-i", "pipe:0",
                             "-pix_fmt", pix_fmt, "-f", "rawvideo", "-"]
    proc = subprocess.Popen(ff_cmd, stdin=rpicam.stdout,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, bufsize=0)
    proc._child = rpicam
    return proc


def take_snapshot(path, w, h, rotate=True, timeout=10):
    """Capture one still to path. Returns path on success, else None."""
    dev = find_uvc_device()
    if dev:
        cmd = _FFMPEG_BASE + ["-y", "-f", "v4l2", "-i", dev,
                              "-frames:v", "1",
                              "-vf", _uvc_vf(w, h, None, rotate),
                              "-q:v", "3", path]
    else:
        cmd = (["rpicam-still", "-o", path, "--width", str(w),
                "--height", str(h), "-t", "300", "--nopreview", "-q", "90"]
               + _rpicam_rot(rotate))
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    return path if os.path.isfile(path) else None


def start_recording(path, w, h, fps=30, rotate=True):
    """Start an open-ended H.264 recording. Stop with stop_recording(proc)."""
    dev = find_uvc_device()
    if dev:
        cmd = _FFMPEG_BASE + ["-y", "-f", "v4l2", "-i", dev,
                              "-vf", _uvc_vf(w, h, fps, rotate),
                              "-c:v", "libx264", "-preset", "veryfast",
                              "-pix_fmt", "yuv420p", "-f", "h264", path]
    else:
        cmd = (["rpicam-vid", "-o", path, "--width", str(w),
                "--height", str(h), "--framerate", str(fps), "-t", "0",
                "--nopreview", "--codec", "h264"]
               + _rpicam_rot(rotate))
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def record_clip(path, w, h, duration, fps=30, rotate=True):
    """Blocking fixed-length recording. Returns path on success, else None."""
    dev = find_uvc_device()
    if dev:
        cmd = _FFMPEG_BASE + ["-y", "-f", "v4l2", "-i", dev,
                              "-t", str(duration),
                              "-vf", _uvc_vf(w, h, fps, rotate),
                              "-c:v", "libx264", "-preset", "veryfast",
                              "-pix_fmt", "yuv420p", "-f", "h264", path]
    else:
        cmd = (["rpicam-vid", "-o", path, "--width", str(w),
                "--height", str(h), "--framerate", str(fps),
                "-t", str(duration * 1000), "--nopreview", "--codec", "h264"]
               + _rpicam_rot(rotate))
    try:
        subprocess.run(cmd, capture_output=True, timeout=duration + 10)
    except subprocess.TimeoutExpired:
        return None
    return path if os.path.isfile(path) else None


def stop_recording(proc, timeout=5):
    """SIGINT a recording so ffmpeg/rpicam finalises the file, then reap it."""
    if proc is None:
        return
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except OSError:
        pass
