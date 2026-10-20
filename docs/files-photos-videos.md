# Sending files, photos and videos

socketchat can send any file to a chat, and only the people in that chat can open it. This page explains how sending works in plain words, and what encryption cannot do for you once a file arrives. Please read the limits before you send something private.

## How sending works

When you send a file, your app locks it with a new key made for that file alone. It uploads the locked file to the server in small pieces, then tells the chat, in an encrypted message, the file's name, its size and the key to unlock it. The server holds only the locked pieces. It never has the key, so it cannot see what is inside.

When someone in the chat saves the file, their app downloads the pieces, unlocks them, and checks that the file is exactly what you sent. If anything changed on the way, it saves nothing and says so.

Photos get one extra step before sending: your app removes the hidden data described below.

## Commands

In the chat screen, type:

- `/send <path>` to send a file, photo or video to the chat you have open. For example: `/send ~/Pictures/beach.jpg`
- `/save <file>` to save a file someone sent, using the name shown in the chat. It goes to your Downloads folder.
- `/save <file> <folder>` to save it somewhere else. For example: `/save beach.jpg ~/Desktop`

Saving never replaces a file you already have. If `beach.jpg` exists, the new one becomes `beach (1).jpg`.

## Videos ask first

Before sending a video, socketchat stops and asks:

> beach.mp4 may still hold the place it was filmed and the phone that made it. socketchat removes this from photos but cannot remove it from videos. Send it anyway?

Press Y to send it or N to cancel.

## Receivers control what you send

Once a file arrives, the people in the chat can save it, copy it, screenshot it or forward it. Encryption protects a file while it travels and while it waits on the server. After it arrives, it is in the receiver's hands. Send only what you are comfortable with everyone in that chat keeping.

## Photos carry hidden data

Phone photos usually hold hidden details, called EXIF data: the place the photo was taken and the phone that took it. socketchat removes these details from JPEG, PNG and WebP photos before sending, without changing the picture.

iPhones often save photos in a format called HEIC. socketchat cannot clean HEIC photos, so it treats them like videos and asks before sending.

## Videos keep their hidden data

socketchat does not remove location or device details from videos. That is why it asks before sending one. If the place a video was filmed is private, remove that data with another tool first, or do not send it.

Other files, such as PDFs and documents, are sent exactly as they are. Some hold hidden details of their own, such as the author's name.

## No take-backs

Once a file is sent, you cannot unsend it. Deleting a file removes your copy only.

## The server sees size and timing

The server cannot see what is in a file, but it sees how big the locked file is and when it moves. Someone watching the server could tell that a large file went to a chat at a certain time.

## Size limit

Each server sets a largest file size. The default is 100 MB. If a file is too big, the server refuses it before any of it is uploaded.

## Files expire

The server deletes a file once everyone in the chat has saved it, or after the server's retention period (30 days by default), whichever comes first. If you wait longer than that to save a file, it is gone, and the sender needs to send it again.
