# Sending files, photos and videos

Socketchat can send any file to a chat, and only the people in that chat can open it. This page explains how sending works in plain words, and what encryption cannot do for you once a file arrives. Please read the limits before you send something private.

## How sending works

When you send a file, your app locks it with a new key made for that file alone. It uploads the locked file to the server in small pieces, then tells the chat, in an encrypted message, the file's name, its size and the key to unlock it. The server holds only the locked pieces. It never has the key, so it cannot see what is inside.

When someone in the chat saves the file, their app downloads the pieces, unlocks them, and checks that the file is exactly what you sent. If anything changed on the way, it saves nothing and says so.

Photos get one extra step before sending: your app removes the hidden data described below.

## Commands

In the chat screen, type:

- `/send <path>` to send a file, photo or video to the chat you have open. For example: `/send ~/Pictures/beach.jpg`. You can also drag a file onto the window: the message box shows `[File 1]`, and Enter sends it.
- `/save` to save the newest file someone else sent in the chat. It goes to your Downloads folder.
- `/save <file>` to save a file by the name shown in the chat. `/save ` and Tab, or Up and Down, go through the chat's files, newest first.
- `/save <file> <folder>` to save it somewhere else. For example: `/save beach.jpg ~/Desktop`

The line that says someone sent a file also says how to save it, for example "Ana sent beach.jpg (2.1 MB). Type /save beach.jpg to save it to Downloads." While the mouse is on, a click on that line saves the file to Downloads, and a second click says where it went. After a save, a line that only you see says where the file went, for example "Saved beach.jpg to ~/Downloads/beach.jpg." On a computer with no Downloads folder, files go to the folder Socketchat started in, and the lines say so.

Enter never sends the path of a file on your computer as a message. Some terminals type a dropped file's path instead of pasting it; when the message box holds nothing but such a path, Enter attaches the file as `[File 1]`, and the next Enter sends it.

When more than one file in the chat has the same name, `/save` saves nothing. It lists the three newest instead, each with a number, the person who sent it and the time it arrived, and gives the numbers of any older ones. Add the number after a colon to save that one, for example `/save beach.jpg:2`. Put a name with spaces in quotes: `/save "beach day.jpg":2`. The line for each file already shows the command that saves it.

Saving never replaces a file you already have. If `beach.jpg` exists, the new one becomes `beach (1).jpg`. On macOS and Linux, a saved file can be read only by your account.

While a file downloads, Socketchat writes it to a hidden file whose name starts with `.socketchat-` in the same folder. If a download stops partway, that file stays behind. On macOS and Linux, Socketchat deletes it the next time you save the same file, an hour or more later.

A saved file's name never starts with a dot, which would hide it, and never ends with a dot or a space. A name that Windows keeps for a device, such as `CON`, `NUL` or `COM1.txt`, gets an underscore in front, so it saves as a normal file.

## Videos and some photos ask first

Before sending a video, Socketchat stops and asks:

> beach.mp4 may still hold the place it was filmed and the phone that made it. Socketchat removes this from photos but cannot remove it from videos. Send it anyway?

Before sending a photo it cannot clean (see below), it asks:

> beach.heic may still hold the place it was taken and the phone that took it. Socketchat cannot remove this from this photo. Send it anyway?

Press Y to send it. Any other key cancels, and while the mouse is on, the Yes and No buttons answer too. A key pressed before the question showed never answers it.

## Receivers control what you send

Once a file arrives, the people in the chat can save it, copy it, screenshot it or forward it. Encryption protects a file while it travels and while it waits on the server. After it arrives, it is in the receiver's hands. Send only what you are comfortable with everyone in that chat keeping.

## Photos carry hidden data

Phone photos usually hold hidden details, called EXIF data: the place the photo was taken and the phone that took it. Socketchat removes these details from JPEG, PNG, WebP and GIF images before sending, without changing the picture's pixels.

To do this, Socketchat writes a new copy of the photo that keeps only what a viewer needs to draw the picture. Hidden details go wherever they sit in the file: in the small preview image (thumbnail), in the second images some phones add to a photo for depth, extra-bright highlights or a short motion clip, and in anything stored after the picture. A motion photo therefore arrives as a still photo. A JPEG keeps one detail, the way the phone was turned, so a photo taken sideways still shows the right way up. A GIF keeps its frames, their timing and how many times it loops, and loses its comments and any other added data. Color profiles go too, so a photo with extra-wide color can look a little less vivid on some screens.

iPhones often save photos in a format called HEIC. Socketchat cannot clean HEIC photos, or TIFF, camera raw, JPEG XL, JPEG 2000 and Photoshop files, so it asks before sending them, as it does for videos. It also asks before sending a JPEG, PNG, WebP or GIF image larger than 100 MiB (about 105 MB), or one it cannot read, because it cannot clean those either.

## Videos keep their hidden data

Socketchat does not remove location or device details from videos. That is why it asks before sending one. If the place a video was filmed is private, remove that data with another tool first, or do not send it.

Other files, such as PDFs and documents, are sent exactly as they are. Some hold hidden details of their own, such as the author's name.

## No take-backs

Once a file is sent, you cannot unsend it. Deleting a file removes your copy only.

## The server sees size and timing

The server cannot see what is in a file, but it sees how big the locked file is and when it moves. Someone watching the server could tell that a large file went to a chat at a certain time.

## Size limit

Each server sets a largest file size. The default is 100 MB. If a file is too big, the server refuses it before any of it is uploaded.

A server also limits how much one room, one person in a room and the whole server keep at once. Past a limit it refuses new files with a reason, such as "this server is full", until members save older files or they expire.

## Files expire

The server deletes a file once everyone in the chat has saved it, or after the server's retention period (30 days by default), whichever comes first. If you wait longer than that to save a file, it is gone, and the sender needs to send it again.
