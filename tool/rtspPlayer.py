import os
import threading
import tkinter as tk
from tkinter import messagebox
import cv2
from PIL import Image, ImageTk

class SimpleRTSPPlayer:
    def __init__(self, root):
        """
        Initialize the main GUI window and application states.
        """
        self.root = root
        self.root.title("Simple RTSP Player (Secure Input)")
        self.root.geometry("800x600")
        self.root.configure(bg="#2c3e50")
        
        # Handle the window close event to clean up resources gracefully
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)

        # Application state variables
        self.is_playing = False
        self.cap = None
        self.current_frame = None
        self.frame_lock = threading.Lock()

        # --- Top Control Panel ---
        self.control_frame = tk.Frame(self.root, bg="#34495e", pady=10)
        self.control_frame.pack(side=tk.TOP, fill=tk.X)

        # RTSP URL Entry Label
        self.lbl_url = tk.Label(self.control_frame, text="RTSP Stream URL:", fg="white", bg="#34495e", font=("Arial", 10, "bold"))
        self.lbl_url.pack(side=tk.LEFT, padx=(10, 5))

        # --- FAKE COMPOSITE ENTRY BOX (Visual trick for masked RTSP URL) ---
        # A container that looks exactly like a standard text entry
        self.url_frame = tk.Frame(self.control_frame, bg="white", bd=2, relief=tk.SUNKEN)
        self.url_frame.pack(side=tk.LEFT, padx=5)

        # Prefix Label (Always visible as 'rtsp://')
        self.lbl_prefix = tk.Label(self.url_frame, text="rtsp://", bg="white", fg="black", font=("Arial", 10))
        self.lbl_prefix.pack(side=tk.LEFT, padx=(2, 0))

        # StringVar to hold the background real URL payload and monitor changes
        self.url_var = tk.StringVar()
        self.url_var.trace_add("write", self.on_url_input)

        # Actual Entry configured as a password field (shows asterisks)
        self.url_entry = tk.Entry(
            self.url_frame, 
            textvariable=self.url_var, 
            width=50, 
            bd=0, 
            highlightthickness=0, 
            font=("Arial", 10), 
            show="*",
            disabledbackground="#ececec"
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 2), pady=2)

        # Make the fake frame behave like a real entry field when clicked anywhere inside
        self.url_frame.bind("<Button-1>", lambda e: self.url_entry.focus_set())
        self.lbl_prefix.bind("<Button-1>", lambda e: self.url_entry.focus_set())

        # Default Example URL Payload (will be rendered as 'rtsp://********************')
        self.url_var.set("admin:password@192.168.1.100:554/stream1")
        # -------------------------------------------------------------------

        # Play Button
        self.btn_play = tk.Button(self.control_frame, text="Play", command=self.start_stream, width=10, bg="#27ae60", fg="white", font=("Arial", 9, "bold"))
        self.btn_play.pack(side=tk.LEFT, padx=5)

        # Stop Button
        self.btn_stop = tk.Button(self.control_frame, text="Stop", command=self.stop_stream, state=tk.DISABLED, width=10, bg="#c0392b", fg="white", font=("Arial", 9, "bold"))
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        # --- Video Display Area ---
        self.video_label = tk.Label(self.root, bg="black", text="No Video Signal", fg="gray", font=("Arial", 20))
        self.video_label.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

    def on_url_input(self, *args):
        """
        Intercepts user input or paste events.
        If the user pastes a full URL starting with 'rtsp://', this strips the prefix 
        to prevent duplication and ensures it displays correctly with asterisks.
        """
        val = self.url_var.get()
        # Check if the pasted string contains 'rtsp://'
        if val.strip().lower().startswith("rtsp://"):
            # Find the exact index to safely strip the protocol while keeping everything else
            idx = val.lower().find("rtsp://")
            self.url_var.set(val[idx+7:])
            # Safely move cursor to the end after Tkinter resolves internal trace events
            self.root.after(0, lambda: self.url_entry.icursor(tk.END))

    def set_url_input_state(self, state):
        """Helper to visually disable/enable the composite URL input box."""
        self.url_entry.config(state=state)
        bg_color = "#ececec" if state == tk.DISABLED else "white"
        self.url_frame.config(bg=bg_color)
        self.lbl_prefix.config(bg=bg_color)

    def start_stream(self):
        """
        Triggered when the Play button is clicked. 
        Reconstructs the full URL, validates it, and starts the processing thread.
        """
        url_suffix = self.url_var.get().strip()
        if not url_suffix:
            messagebox.showerror("Error", "Please enter a valid RTSP URL suffix.")
            return

        # Reconstruct the real full URL behind the scenes
        full_url = f"rtsp://{url_suffix}"

        # Update UI states
        self.is_playing = True
        self.btn_play.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        
        # Visually disable the custom composite entry field
        self.set_url_input_state(tk.DISABLED)
        
        self.video_label.config(text="Connecting to RTSP stream...", fg="white")

        # Start a background thread to read video frames to avoid freezing the GUI
        self.video_thread = threading.Thread(target=self.process_video_stream, args=(full_url,))
        self.video_thread.daemon = True
        self.video_thread.start()

        # Start the GUI update loop
        self.update_gui()

    def process_video_stream(self, url):
        """
        Runs in a separate thread. Connects to the RTSP stream and continuously reads frames.
        """
        # Force OpenCV to use TCP for RTSP streams to reduce packet loss and gray artifacts over LAN
        os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp"
        
        self.cap = cv2.VideoCapture(url)
        # Minimize buffer size to reduce stream latency
        self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

        if not self.cap.isOpened():
            if self.is_playing:
                self.root.after(0, self.show_error, "Failed to connect to the RTSP stream.\nPlease check the URL or your network connection.")
                self.root.after(0, self.stop_stream)
            return

        while self.is_playing and self.cap.isOpened():
            ret, frame = self.cap.read()
            if ret:
                # Convert BGR (OpenCV default) to RGB (Pillow format)
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                
                # Safely update the current frame using a lock
                with self.frame_lock:
                    self.current_frame = frame_rgb
            else:
                # Reached end of stream or stream disconnected
                break

        # Cleanup when the loop exits
        if self.cap:
            self.cap.release()
            self.cap = None
            
        # If the thread stops abnormally (e.g., connection lost), notify the main thread
        if self.is_playing:
            self.root.after(0, self.show_error, "Stream disconnected or ended.")
            self.root.after(0, self.stop_stream)

    def update_gui(self):
        """
        Runs in the main GUI thread. Fetches the latest frame and updates the label.
        """
        if not self.is_playing:
            return

        frame = None
        # Safely fetch and consume the current frame
        with self.frame_lock:
            if self.current_frame is not None:
                frame = self.current_frame
                self.current_frame = None  # Clear frame after fetching

        if frame is not None:
            # Get current size of the video display label
            label_width = self.video_label.winfo_width()
            label_height = self.video_label.winfo_height()

            # Maintain aspect ratio while dynamically resizing
            if label_width > 10 and label_height > 10:
                h, w, _ = frame.shape
                scale = min(label_width / w, label_height / h)
                new_w, new_h = int(w * scale), int(h * scale)
                frame = cv2.resize(frame, (new_w, new_h))

            # Convert the array to a PIL Image, then to a Tkinter compatible PhotoImage
            pil_image = Image.fromarray(frame)
            tk_image = ImageTk.PhotoImage(image=pil_image)

            # Update the UI safely in the main thread
            self.video_label.config(image=tk_image, text="")
            self.video_label.image = tk_image  # Keep a reference to prevent garbage collection

        # Schedule the next GUI update in 30 milliseconds (~33 FPS)
        self.root.after(30, self.update_gui)

    def show_error(self, message):
        """Shows an error message dialog."""
        messagebox.showerror("Stream Error", message)

    def stop_stream(self):
        """Stops the video stream and resets the UI states."""
        if not self.is_playing:
            return
            
        self.is_playing = False
        
        # Reset UI elements
        self.btn_play.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        
        # Visually restore the custom composite entry field
        self.set_url_input_state(tk.NORMAL)
        
        # Clear video display
        self.video_label.config(image='', text="No Video Signal", fg="gray")
        
        # Clear frame data
        with self.frame_lock:
            self.current_frame = None

    def on_window_close(self):
        """Handles the window close event to terminate background threads safely."""
        self.is_playing = False
        self.root.destroy()

if __name__ == "__main__":
    # Create the main Tkinter window
    root = tk.Tk()
    
    # Initialize the RTSP player application
    app = SimpleRTSPPlayer(root)
    
    # Start the GUI event loop
    root.mainloop()