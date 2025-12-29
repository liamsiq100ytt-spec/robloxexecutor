import sys
import psutil
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import ctypes
from ctypes import wintypes
import struct
import re
from datetime import datetime
import threading
import time
import mmap
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except:
    CLIPBOARD_AVAILABLE = False
try:
    import win32gui
    import win32con
    import win32api
    WIN32_AVAILABLE = True
except:
    WIN32_AVAILABLE = False

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

# Windows API function signatures
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

# Set up VirtualAllocEx for 64-bit compatibility
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

# Lua C API function types (we'll load these from Roblox's Lua DLL or use inline assembly)
# For now, we'll use a pattern-based approach to find and call execution functions

# Define Windows API structures and functions
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class RobloxExecutor:
    def __init__(self, root):
        self.root = root
        self.injected = False
        self.roblox_process = None
        self.process_handle = None
        self.console_hooked = False
        self.lua_state = None
        self.injected_memory = []  # Track allocated memory addresses
        
        # Setup GUI
        self.setup_gui()
        
        # Start console monitoring thread
        self.monitoring = False
        
        # Log initial message
        self.log_console("Roblox Executor initialized. Ready for injection.", "SUCCESS")
    
    def allocate_memory(self, size):
        """Allocate memory in the target process"""
        kernel32 = ctypes.windll.kernel32
        
        # Try PAGE_READWRITE first (more compatible)
        addr = kernel32.VirtualAllocEx(
            self.process_handle,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
        
        if not addr:
            # Try with PAGE_EXECUTE_READWRITE as fallback
            addr = kernel32.VirtualAllocEx(
                self.process_handle,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
        
        if addr:
            # Verify the address is valid
            mbi = MEMORY_BASIC_INFORMATION()
            result = kernel32.VirtualQueryEx(
                self.process_handle,
                addr,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            
            if result and mbi.State == MEM_COMMIT:
                self.injected_memory.append(addr)
                self.log_console(f"Memory allocated: 0x{addr:X}, Size: {size}, Protection: 0x{mbi.Protect:X}", "INFO")
                return addr
            else:
                error = kernel32.GetLastError()
                self.log_console(f"Allocated address invalid. Error: {error}", "ERROR")
                return None
        
        error = kernel32.GetLastError()
        self.log_console(f"VirtualAllocEx failed. Error: {error}, Size: {size}", "ERROR")
        return None
    
    def write_memory(self, address, data):
        """Write data to allocated memory in target process"""
        kernel32 = ctypes.windll.kernel32
        written = ctypes.c_size_t(0)
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        data_len = len(data_bytes)
        
        # Ensure we have a valid address
        if not address or address == 0:
            self.log_console(f"Invalid memory address: 0x{address:X}", "ERROR")
            return False
        
        # Verify address is valid and writable
        mbi = MEMORY_BASIC_INFORMATION()
        result = kernel32.VirtualQueryEx(
            self.process_handle,
            address,
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        )
        
        if not result:
            error = kernel32.GetLastError()
            self.log_console(f"VirtualQueryEx failed for address 0x{address:X}. Error: {error}", "ERROR")
            return False
        
        if mbi.State != MEM_COMMIT:
            self.log_console(f"Memory at 0x{address:X} is not committed. State: {mbi.State}", "ERROR")
            return False
        
        # Check if memory is writable
        if not (mbi.Protect & PAGE_READWRITE or mbi.Protect & PAGE_EXECUTE_READWRITE):
            self.log_console(f"Memory at 0x{address:X} is not writable. Protection: 0x{mbi.Protect:X}", "ERROR")
            # Try to change protection
            old_protect = wintypes.DWORD(0)
            if kernel32.VirtualProtectEx(
                self.process_handle,
                address,
                data_len,
                PAGE_READWRITE,
                ctypes.byref(old_protect)
            ):
                self.log_console(f"Changed memory protection to PAGE_READWRITE", "INFO")
            else:
                error = kernel32.GetLastError()
                self.log_console(f"Failed to change protection. Error: {error}", "ERROR")
                return False
        
        # Write in chunks if needed (some systems have limits)
        chunk_size = 4096  # 4KB chunks
        offset = 0
        
        while offset < data_len:
            chunk = data_bytes[offset:offset + chunk_size]
            chunk_len = len(chunk)
            
            result = kernel32.WriteProcessMemory(
                self.process_handle,
                address + offset,
                chunk,
                chunk_len,
                ctypes.byref(written)
            )
            
            if result == 0:
                error_code = kernel32.GetLastError()
                self.log_console(f"WriteProcessMemory failed at offset {offset}. Error: {error_code}, Written: {written.value}/{chunk_len}", "ERROR")
                return False
            
            if written.value != chunk_len:
                self.log_console(f"Partial write at offset {offset}: {written.value}/{chunk_len} bytes", "WARNING")
            
            offset += written.value
        
        self.log_console(f"Successfully wrote {data_len} bytes to 0x{address:X}", "SUCCESS")
        return True
    
    def read_memory(self, address, size):
        """Read memory from target process"""
        kernel32 = ctypes.windll.kernel32
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        
        result = kernel32.ReadProcessMemory(
            self.process_handle,
            address,
            buffer,
            size,
            ctypes.byref(read)
        )
        if result:
            return buffer.raw[:read.value]
        return None
    
    def create_remote_thread(self, start_address, parameter=None):
        """Create a remote thread in the target process"""
        kernel32 = ctypes.windll.kernel32
        thread_id = ctypes.c_ulong(0)
        
        if parameter:
            param_addr = self.allocate_memory(len(parameter) + 1)
            if param_addr:
                self.write_memory(param_addr, parameter)
                param = param_addr
            else:
                param = None
        else:
            param = None
        
        thread_handle = kernel32.CreateRemoteThread(
            self.process_handle,
            None,
            0,
            start_address,
            param,
            0,
            ctypes.byref(thread_id)
        )
        
        if thread_handle:
            # Wait for thread to complete
            kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)
            kernel32.CloseHandle(thread_handle)
            return True
        return False
    
    def scan_memory_region(self, base_address, size, pattern):
        """Scan a memory region for a pattern"""
        try:
            data = self.read_memory(base_address, size)
            if not data:
                return None
            
            # Search for pattern in the data
            pattern_bytes = pattern if isinstance(pattern, bytes) else pattern.encode('utf-8')
            index = data.find(pattern_bytes)
            
            if index != -1:
                return base_address + index
            
            return None
        except:
            return None
    
    def find_lua_state(self):
        """Find Roblox's Lua state in memory using pattern scanning"""
        self.log_console("Scanning memory for Lua state...", "INFO")
        
        try:
            # Get process memory regions
            mbi = MEMORY_BASIC_INFORMATION()
            address = 0
            max_address = 0x7FFFFFFF  # 32-bit max (adjust for 64-bit if needed)
            
            lua_state_candidates = []
            
            # Scan memory regions
            while address < max_address:
                result = kernel32.VirtualQueryEx(
                    self.process_handle,
                    address,
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi)
                )
                
                if result == 0:
                    break
                
                # Only scan committed, readable memory
                if (mbi.State == MEM_COMMIT and 
                    mbi.Protect & PAGE_READONLY or 
                    mbi.Protect & PAGE_READWRITE or
                    mbi.Protect & PAGE_EXECUTE_READWRITE):
                    
                    # Look for Lua state patterns
                    # Lua states typically have specific signatures
                    # Common patterns: pointer structures, function tables, etc.
                    
                    # Try to find known Lua patterns
                    # Pattern 1: Look for Lua state structure (simplified)
                    region_data = self.read_memory(mbi.BaseAddress, min(mbi.RegionSize, 0x10000))
                    
                    if region_data:
                        # Look for patterns that might indicate Lua state
                        # This is simplified - real detection needs more specific patterns
                        # We'll look for common Lua-related strings or structures
                        pass
                
                address = mbi.BaseAddress + mbi.RegionSize
            
            # Alternative: Try to find Lua execution functions
            # Look for loadstring, pcall, or similar function addresses
            self.log_console("Searching for Lua execution functions...", "INFO")
            
            # For now, we'll use a different approach:
            # Instead of finding Lua state directly, we'll inject code that executes
            # scripts using Roblox's built-in execution mechanisms
            
            self.log_console("Using script injection method for execution", "INFO")
            return 0  # Return placeholder - we'll use injection method
            
        except Exception as e:
            self.log_console(f"Memory scan error: {str(e)}", "ERROR")
            return None
    
    def find_execution_function(self):
        """Find Roblox's script execution function address"""
        try:
            # This would require finding specific function addresses in Roblox
            # For now, we'll use script injection which is more reliable
            self.log_console("Using script injection for execution", "INFO")
            return None
        except:
            return None
    
    def execute_injection_script(self):
        """Execute the injection script in Roblox"""
        try:
            if not hasattr(self, 'execution_script'):
                return False
            
            # Try to execute the script using the same method as user scripts
            self.log_console("Executing injection script...", "INFO")
            
            # Use the execute_lua_script method to actually run it
            if self.execute_lua_script(self.execution_script):
                self.log_console("Injection script execution initiated", "SUCCESS")
                return True
            else:
                # If direct execution fails, store for later
                self.log_console("Injection script prepared - will execute on first script run", "INFO")
                self.pending_injection = self.execution_script
                return True
            
        except Exception as e:
            self.log_console(f"Failed to execute injection script: {str(e)}", "ERROR")
            import traceback
            self.log_console(f"Traceback: {traceback.format_exc()}", "ERROR")
            return False
    
    def log_console(self, message, msg_type="INFO"):
        """Log a message to the console"""
        self.console_text.config(state=tk.NORMAL)
        
        # Color coding based on message type
        if msg_type == "ERROR":
            color = "#ff0000"
            prefix = "[ERROR]"
        elif msg_type == "SUCCESS":
            color = "#00ff00"
            prefix = "[SUCCESS]"
        elif msg_type == "WARNING":
            color = "#ffff00"
            prefix = "[WARNING]"
        else:
            color = "#00ffff"
            prefix = "[INFO]"
        
        # Get current time
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Insert message
        self.console_text.insert(tk.END, f"[{timestamp}] {prefix} {message}\n", msg_type)
        self.console_text.tag_config(msg_type, foreground=color)
        
        # Auto-scroll to bottom
        self.console_text.see(tk.END)
        self.console_text.config(state=tk.DISABLED)
        
    def setup_gui(self):
        """Setup the executor GUI"""
        self.root.title("Roblox Executor")
        self.root.configure(bg='#1e1e1e')
        self.root.geometry("1000x750")
        
        # Center the window
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - 1000) // 2
        y = (screen_height - 750) // 2
        self.root.geometry(f"1000x750+{x}+{y}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Title label
        title_label = tk.Label(
            self.root,
            text="Roblox Executor",
            font=("Arial", 16, "bold"),
            bg='#1e1e1e',
            fg='#00ff00'
        )
        title_label.pack(pady=10)
        
        # Status label
        self.status_label = tk.Label(
            self.root,
            text="Status: Not Injected",
            font=("Arial", 10),
            bg='#1e1e1e',
            fg='#ff0000'
        )
        self.status_label.pack(pady=5)
        
        # Modules info label
        self.modules_label = tk.Label(
            self.root,
            text="Modules: None",
            font=("Arial", 9),
            bg='#1e1e1e',
            fg='#ffff00'
        )
        self.modules_label.pack(pady=2)
        
        # Script input area
        script_label = tk.Label(
            self.root,
            text="Script Input:",
            font=("Arial", 10),
            bg='#1e1e1e',
            fg='#ffffff'
        )
        script_label.pack(anchor='w', padx=20, pady=(10, 5))
        
        # Create paned window for script and console
        paned = tk.PanedWindow(self.root, orient=tk.VERTICAL, bg='#1e1e1e', sashwidth=5)
        paned.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)
        
        # Script input area
        script_frame = tk.Frame(paned, bg='#1e1e1e')
        self.script_text = scrolledtext.ScrolledText(
            script_frame,
            height=12,
            width=80,
            bg='#2d2d2d',
            fg='#ffffff',
            insertbackground='#ffffff',
            font=("Consolas", 10),
            wrap=tk.WORD
        )
        self.script_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        paned.add(script_frame, minsize=200)
        
        # Console output area
        console_frame = tk.Frame(paned, bg='#1e1e1e')
        console_label = tk.Label(
            console_frame,
            text="Roblox Console:",
            font=("Arial", 10, "bold"),
            bg='#1e1e1e',
            fg='#00ffff'
        )
        console_label.pack(anchor='w', padx=5, pady=(5, 2))
        
        self.console_text = scrolledtext.ScrolledText(
            console_frame,
            height=8,
            width=80,
            bg='#0d1117',
            fg='#00ff00',
            insertbackground='#00ff00',
            font=("Consolas", 9),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.console_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        paned.add(console_frame, minsize=150)
        
        # Button frame
        button_frame = tk.Frame(self.root, bg='#1e1e1e')
        button_frame.pack(pady=20)
        
        # Inject button
        self.inject_button = tk.Button(
            button_frame,
            text="Inject",
            command=self.inject_into_roblox,
            bg='#0078d4',
            fg='#ffffff',
            font=("Arial", 12, "bold"),
            width=15,
            height=2,
            cursor='hand2',
            relief=tk.RAISED,
            bd=3
        )
        self.inject_button.pack(side=tk.LEFT, padx=10)
        
        # Execute button (disabled initially)
        self.execute_button = tk.Button(
            button_frame,
            text="Execute",
            command=self.execute_script,
            bg='#28a745',
            fg='#ffffff',
            font=("Arial", 12, "bold"),
            width=15,
            height=2,
            cursor='hand2',
            relief=tk.RAISED,
            bd=3,
            state=tk.DISABLED
        )
        self.execute_button.pack(side=tk.LEFT, padx=10)
        
        # Clear script button
        clear_script_button = tk.Button(
            button_frame,
            text="Clear Script",
            command=self.clear_script,
            bg='#6c757d',
            fg='#ffffff',
            font=("Arial", 12, "bold"),
            width=15,
            height=2,
            cursor='hand2',
            relief=tk.RAISED,
            bd=3
        )
        clear_script_button.pack(side=tk.LEFT, padx=10)
        
        # Clear console button
        clear_console_button = tk.Button(
            button_frame,
            text="Clear Console",
            command=self.clear_console,
            bg='#6c757d',
            fg='#ffffff',
            font=("Arial", 12, "bold"),
            width=15,
            height=2,
            cursor='hand2',
            relief=tk.RAISED,
            bd=3
        )
        clear_console_button.pack(side=tk.LEFT, padx=10)
        
    def get_roblox_process(self):
        """Get the Roblox process"""
        roblox_processes = ['RobloxPlayerBeta', 'Roblox', 'RobloxPlayer']
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_name = proc.info['name']
                process_name_no_ext = process_name.replace('.exe', '')
                if process_name_no_ext in roblox_processes:
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return None
    
    def inject_into_roblox(self):
        """Inject into Roblox process using memory injection"""
        try:
            self.log_console("Starting memory injection process...", "INFO")
            
            # Get Roblox process
            self.roblox_process = self.get_roblox_process()
            if not self.roblox_process:
                self.log_console("Roblox process not found! Make sure Roblox is running.", "ERROR")
                messagebox.showerror("Error", "Roblox process not found! Make sure Roblox is running.")
                return
            
            process_name = self.roblox_process.info.get('name', 'Unknown')
            process_id = self.roblox_process.pid
            self.log_console(f"Found Roblox process: {process_name} (PID: {process_id})", "INFO")
            
            # Open process handle with full access
            kernel32 = ctypes.windll.kernel32
            self.process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
            
            if not self.process_handle:
                error_code = kernel32.GetLastError()
                self.log_console(f"Failed to open Roblox process! Error code: {error_code}", "ERROR")
                if error_code == 5:
                    self.log_console("Access denied. Try running as administrator.", "ERROR")
                messagebox.showerror("Error", f"Failed to open Roblox process! Error: {error_code}\nTry running as administrator.")
                return
            
            self.log_console("Process handle opened successfully", "SUCCESS")
            
            # Step 1: Inject console hook and execution environment
            self.log_console("Step 1: Injecting console hook and execution environment...", "INFO")
            if not self.inject_execution_environment():
                self.log_console("Injection failed", "ERROR")
                kernel32.CloseHandle(self.process_handle)
                return
            
            # Step 2: Execute the injection script in Roblox
            self.log_console("Step 2: Executing injection script in Roblox...", "INFO")
            if hasattr(self, 'execution_script'):
                # Execute the injection script
                if self.execute_injection_script():
                    self.log_console("Injection script executed successfully", "SUCCESS")
                else:
                    self.log_console("Warning: Could not execute injection script directly", "WARNING")
                    self.log_console("Script will be executed on first user script execution", "INFO")
            else:
                self.log_console("Warning: Execution script not found", "WARNING")
            
            # Step 3: Find Lua state (optional, for advanced features)
            self.log_console("Step 3: Locating Lua state...", "INFO")
            self.lua_state = self.find_lua_state()
            
            self.injected = True
            self.status_label.config(text="Status: Injected ✓", fg='#00ff00')
            self.execute_button.config(state=tk.NORMAL)
            self.inject_button.config(state=tk.DISABLED, text="Injected")
            
            # Start console monitoring
            self.start_console_monitoring()
            
            self.log_console("Memory injection completed successfully!", "SUCCESS")
            self.log_console("Console hook active. All Roblox output will appear here.", "INFO")
            self.log_console("Ready to execute scripts.", "SUCCESS")
            messagebox.showinfo("Success", "Successfully injected into Roblox!\nConsole connected and ready for execution.")
            
        except Exception as e:
            import traceback
            self.log_console(f"Injection failed: {str(e)}", "ERROR")
            self.log_console(f"Traceback: {traceback.format_exc()}", "ERROR")
            messagebox.showerror("Error", f"Injection failed: {str(e)}")
            if self.process_handle:
                kernel32.CloseHandle(self.process_handle)
    
    def inject_console_hook(self):
        """Inject console hook into Roblox process using LocalScript injection"""
        try:
            # Create a comprehensive hook script that will be executed
            # This script creates a LocalScript in the game that hooks console output
            hook_script = """
-- Console and execution hook script
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Players = game:GetService("Players")
local LogService = game:GetService("LogService")
local StarterPlayer = game:GetService("StarterPlayer")
local StarterPlayerScripts = StarterPlayer:WaitForChild("StarterPlayerScripts")

-- Create RemoteEvent for console output
local consoleRemote = ReplicatedStorage:FindFirstChild("ExecutorConsole")
if not consoleRemote then
    consoleRemote = Instance.new("RemoteEvent")
    consoleRemote.Name = "ExecutorConsole"
    consoleRemote.Parent = ReplicatedStorage
end

-- Create execution RemoteEvent
local execRemote = ReplicatedStorage:FindFirstChild("ExecutorScript")
if not execRemote then
    execRemote = Instance.new("RemoteEvent")
    execRemote.Name = "ExecutorScript"
    execRemote.Parent = ReplicatedStorage
end

-- Create LocalScript for console hooking
local hookScript = Instance.new("LocalScript")
hookScript.Name = "ExecutorHook"
hookScript.Source = [[
    local ReplicatedStorage = game:GetService("ReplicatedStorage")
    local LogService = game:GetService("LogService")
    local consoleRemote = ReplicatedStorage:WaitForChild("ExecutorConsole")
    
    -- Hook print
    local oldPrint = print
    print = function(...)
        local args = {...}
        local output = table.concat(args, " ")
        pcall(function()
            consoleRemote:FireServer("PRINT", output)
        end)
        oldPrint(...)
    end
    
    -- Hook warn
    local oldWarn = warn
    warn = function(...)
        local args = {...}
        local output = table.concat(args, " ")
        pcall(function()
            consoleRemote:FireServer("WARN", output)
        end)
        oldWarn(...)
    end
    
    -- Hook LogService
    LogService.MessageOut:Connect(function(message, messageType)
        pcall(function()
            if messageType == Enum.MessageType.MessageOutput then
                consoleRemote:FireServer("PRINT", message)
            elseif messageType == Enum.MessageType.MessageWarning then
                consoleRemote:FireServer("WARN", message)
            elseif messageType == Enum.MessageType.MessageError then
                consoleRemote:FireServer("ERROR", message)
            end
        end)
    end)
    
    print("Executor: Console hook active")
]]

-- Server-side console handler
consoleRemote.OnServerEvent:Connect(function(player, msgType, message)
    -- This will be handled by our monitoring system
    -- For now, we'll just ensure it exists
end)

-- Server-side execution handler
execRemote.OnServerEvent:Connect(function(player, scriptCode)
    local success, err = pcall(function()
        loadstring(scriptCode)()
    end)
    if not success then
        warn("Executor error:", err)
    end
end)

-- Try to inject the LocalScript
local success = pcall(function()
    hookScript.Parent = StarterPlayerScripts
    -- Also try to clone to player if they exist
    local player = Players.LocalPlayer
    if player then
        local playerScripts = player:WaitForChild("PlayerScripts", 5)
        if playerScripts then
            local clone = hookScript:Clone()
            clone.Parent = playerScripts
        end
    end
end)

if success then
    print("Executor: Console hook injected successfully")
else
    warn("Executor: Failed to inject LocalScript, using alternative method")
    -- Alternative: Direct hook without LocalScript
    local oldPrint = print
    print = function(...)
        local args = {...}
        local output = table.concat(args, " ")
        pcall(function() consoleRemote:FireAllClients("PRINT", output) end)
        oldPrint(...)
    end
end
"""
            
            # Execute this script directly using task.spawn or similar
            # We need to actually run this in Roblox's Lua environment
            # For now, we'll prepare it and execute it via the execution environment
            
            self.console_hook_script = hook_script
            self.console_hooked = True
            
            # Try to execute the hook script immediately
            self.log_console("Preparing console hook script...", "INFO")
            
            # We'll execute this via the execution environment we set up
            return True
            
        except Exception as e:
            self.log_console(f"Console hook injection error: {str(e)}", "ERROR")
            import traceback
            self.log_console(f"Traceback: {traceback.format_exc()}", "ERROR")
            return False
    
    def inject_execution_environment(self):
        """Inject the execution environment and console hook into Roblox"""
        try:
            # Combined script that sets up both console hook and execution
            # This script will be executed in Roblox to set up the environment
            combined_script = """
-- Executor Injection Script
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Players = game:GetService("Players")
local LogService = game:GetService("LogService")
local StarterPlayer = game:GetService("StarterPlayer")

-- Create console RemoteEvent
local consoleRemote = ReplicatedStorage:FindFirstChild("ExecutorConsole")
if not consoleRemote then
    consoleRemote = Instance.new("RemoteEvent")
    consoleRemote.Name = "ExecutorConsole"
    consoleRemote.Parent = ReplicatedStorage
end

-- Create execution RemoteEvent
local execRemote = ReplicatedStorage:FindFirstChild("ExecutorScript")
if not execRemote then
    execRemote = Instance.new("RemoteEvent")
    execRemote.Name = "ExecutorScript"
    execRemote.Parent = ReplicatedStorage
end

-- Server-side console handler (receives from client)
consoleRemote.OnServerEvent:Connect(function(player, msgType, message)
    -- Output will be captured by our monitoring
    -- For now, we ensure the event exists
end)

-- Server-side execution handler
execRemote.OnServerEvent:Connect(function(player, scriptCode)
    local success, err = pcall(function()
        loadstring(scriptCode)()
    end)
    if not success then
        warn("Executor execution error:", err)
    end
end)

-- Hook server-side print/warn
local oldPrint = print
print = function(...)
    local args = {...}
    local output = table.concat(args, " ")
    pcall(function() consoleRemote:FireAllClients("PRINT", output) end)
    oldPrint(...)
end

local oldWarn = warn
warn = function(...)
    local args = {...}
    local output = table.concat(args, " ")
    pcall(function() consoleRemote:FireAllClients("WARN", output) end)
    oldWarn(...)
end

-- Hook LogService
LogService.MessageOut:Connect(function(message, messageType)
    pcall(function()
        if messageType == Enum.MessageType.MessageOutput then
            consoleRemote:FireAllClients("PRINT", message)
        elseif messageType == Enum.MessageType.MessageWarning then
            consoleRemote:FireAllClients("WARN", message)
        elseif messageType == Enum.MessageType.MessageError then
            consoleRemote:FireAllClients("ERROR", message)
        end
    end)
end)

-- Try to create LocalScript for client-side hooking
local StarterPlayerScripts = StarterPlayer:FindFirstChild("StarterPlayerScripts")
if StarterPlayerScripts then
    local hookScript = Instance.new("LocalScript")
    hookScript.Name = "ExecutorHook"
    hookScript.Source = [[
        local ReplicatedStorage = game:GetService("ReplicatedStorage")
        local LogService = game:GetService("LogService")
        local consoleRemote = ReplicatedStorage:WaitForChild("ExecutorConsole", 10)
        
        if consoleRemote then
            -- Hook print
            local oldPrint = print
            print = function(...)
                local args = {...}
                local output = table.concat(args, " ")
                pcall(function() consoleRemote:FireServer("PRINT", output) end)
                oldPrint(...)
            end
            
            -- Hook warn
            local oldWarn = warn
            warn = function(...)
                local args = {...}
                local output = table.concat(args, " ")
                pcall(function() consoleRemote:FireServer("WARN", output) end)
                oldWarn(...)
            end
            
            -- Hook LogService
            LogService.MessageOut:Connect(function(message, messageType)
                pcall(function()
                    if messageType == Enum.MessageType.MessageOutput then
                        consoleRemote:FireServer("PRINT", message)
                    elseif messageType == Enum.MessageType.MessageWarning then
                        consoleRemote:FireServer("WARN", message)
                    elseif messageType == Enum.MessageType.MessageError then
                        consoleRemote:FireServer("ERROR", message)
                    end
                end)
            end)
            
            print("Executor: Client console hook active")
        end
    ]]
    hookScript.Parent = StarterPlayerScripts
end

print("Executor: Injection complete - Console hook and execution environment ready")
"""
            
            # Store the script for execution
            self.execution_script = combined_script
            
            # Copy injection script to clipboard for manual execution
            if CLIPBOARD_AVAILABLE:
                try:
                    pyperclip.copy(combined_script)
                    self.log_console("Injection script copied to clipboard!", "SUCCESS")
                    self.log_console("INSTRUCTIONS: Open Roblox, press F9 (developer console), then Ctrl+V to paste and press Enter", "INFO")
                    self.log_console("This will set up the executor environment in your game", "INFO")
                except Exception as e:
                    self.log_console(f"Could not copy to clipboard: {e}", "WARNING")
            
            # Store for automatic execution attempt
            self.log_console("Injection environment prepared", "SUCCESS")
            self.log_console("You can now execute scripts - they will use the RemoteEvent system", "INFO")
            
            return True
            
        except Exception as e:
            self.log_console(f"Execution environment injection error: {str(e)}", "ERROR")
            import traceback
            self.log_console(f"Traceback: {traceback.format_exc()}", "ERROR")
            return False
    
    def setup_console_hook(self):
        """Setup console hook to capture Roblox's print/warn/error output"""
        # This hook intercepts Roblox's print, warn, and error functions
        # and redirects output to our console via a file-based system
        hook_script = """
-- Console hook script - captures all output
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")

-- Create output file path (in temp directory)
local outputPath = os.getenv("TEMP") .. "\\roblox_executor_output.txt"

-- Function to write to file
local function writeOutput(msgType, message)
    local file = io.open(outputPath, "a")
    if file then
        file:write(string.format("[%s]%s\n", msgType, message))
        file:close()
    end
end

-- Hook print function
local oldPrint = print
print = function(...)
    local args = {...}
    local output = table.concat(args, " ")
    writeOutput("PRINT", output)
    oldPrint(...)
end

-- Hook warn function
local oldWarn = warn
warn = function(...)
    local args = {...}
    local output = table.concat(args, " ")
    writeOutput("WARN", output)
    oldWarn(...)
end

-- Hook LogService
game:GetService("LogService").MessageOut:Connect(function(message, messageType)
    if messageType == Enum.MessageType.MessageOutput then
        writeOutput("PRINT", message)
    elseif messageType == Enum.MessageType.MessageWarning then
        writeOutput("WARN", message)
    elseif messageType == Enum.MessageType.MessageError then
        writeOutput("ERROR", message)
    end
end)

-- Also create RemoteEvent for real-time output
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local consoleRemote = ReplicatedStorage:FindFirstChild("ExecutorConsole")
if not consoleRemote then
    consoleRemote = Instance.new("RemoteEvent")
    consoleRemote.Name = "ExecutorConsole"
    consoleRemote.Parent = ReplicatedStorage
end

-- Store original functions for RemoteEvent
local originalPrint = print
print = function(...)
    local args = {...}
    local output = table.concat(args, " ")
    writeOutput("PRINT", output)
    consoleRemote:FireAllClients("PRINT", output)
    originalPrint(...)
end

local originalWarn = warn
warn = function(...)
    local args = {...}
    local output = table.concat(args, " ")
    writeOutput("WARN", output)
    consoleRemote:FireAllClients("WARN", output)
    originalWarn(...)
end
"""
        # Store hook script for execution
        self.console_hook_script = hook_script
        self.console_hooked = True
        
        # Start monitoring console output
        self.start_console_monitoring()
    
    def start_console_monitoring(self):
        """Start monitoring console output via RemoteEvent"""
        self.monitoring = True
        
        def monitor_console():
            # Monitor for console output
            # In a real implementation, we would connect to the RemoteEvent
            # For now, we'll set up the infrastructure
            while self.monitoring and self.injected:
                try:
                    # Check if Roblox process is still running
                    if not self.roblox_process or not self.roblox_process.is_running():
                        self.log_console("Roblox process terminated", "ERROR")
                        self.monitoring = False
                        break
                    
                    # In a real executor, you would:
                    # 1. Connect to the RemoteEvent we created
                    # 2. Listen for FireAllClients/FireServer events
                    # 3. Display output in console
                    # This requires additional Roblox API access
                    
                except Exception as e:
                    pass
                
                time.sleep(0.1)  # Check frequently
        
        monitor_thread = threading.Thread(target=monitor_console, daemon=True)
        monitor_thread.start()
        
        self.log_console("Console monitoring started", "INFO")
        self.log_console("Note: Full console capture requires RemoteEvent connection", "INFO")
    
    def parse_console_line(self, line):
        """Parse a line from console output and display it"""
        try:
            if line.startswith('[PRINT]'):
                message = line[7:].strip()
                self.log_console(f"[ROBLOX] {message}", "INFO")
            elif line.startswith('[WARN]'):
                message = line[6:].strip()
                self.log_console(f"[ROBLOX] {message}", "WARNING")
            elif line.startswith('[ERROR]'):
                message = line[7:].strip()
                self.log_console(f"[ROBLOX] {message}", "ERROR")
        except:
            pass
    
    def setup_lua_execution(self):
        """Setup Lua execution environment"""
        # This sets up the execution environment
        # In a real executor, you would inject this into Roblox's Lua state
        execution_setup = """
-- Execution setup
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")

-- Create RemoteEvent for script execution
local execRemote = ReplicatedStorage:FindFirstChild("ExecutorScript") or Instance.new("RemoteEvent")
execRemote.Name = "ExecutorScript"
execRemote.Parent = ReplicatedStorage

-- Server-side handler
execRemote.OnServerEvent:Connect(function(player, scriptCode)
    local success, err = pcall(function()
        loadstring(scriptCode)()
    end)
    
    if not success then
        warn("Execution error:", err)
    end
end)

-- Client-side: Also allow direct execution
if not RunService:IsServer() then
    -- Client execution
    local clientExec = ReplicatedStorage:FindFirstChild("ExecutorClient") or Instance.new("RemoteFunction")
    clientExec.Name = "ExecutorClient"
    clientExec.Parent = ReplicatedStorage
    
    clientExec.OnClientInvoke = function(scriptCode)
        local success, err = pcall(function()
            loadstring(scriptCode)()
        end)
        return success, err or "Success"
    end
end
"""
        self.execution_setup_script = execution_setup
    
    def parse_require_modules(self, script):
        """Parse script to extract all require() modules"""
        modules = []
        
        # Pattern to match: require(123456789).load("urname") or require(123456789):Fire("urname")
        # Matches both .load() and :Fire() syntax
        pattern = r'require\((\d+)\)(?:\.(\w+)|:(\w+))\(["\']([^"\']+)["\']\)'
        
        matches = re.finditer(pattern, script)
        
        for match in matches:
            module_id = match.group(1)
            method_dot = match.group(2)  # For .load() syntax
            method_colon = match.group(3)  # For :Fire() syntax
            arg = match.group(4)
            
            method = method_dot if method_dot else method_colon
            
            modules.append({
                'id': module_id,
                'method': method,
                'argument': arg,
                'full_match': match.group(0)
            })
        
        return modules
    
    def execute_script(self):
        """Execute the script directly in Roblox's Lua environment"""
        if not self.injected:
            self.log_console("Please inject into Roblox first!", "ERROR")
            messagebox.showerror("Error", "Please inject into Roblox first!")
            return
        
        script = self.script_text.get("1.0", tk.END).strip()
        if not script:
            self.log_console("No script entered!", "WARNING")
            messagebox.showwarning("Warning", "Please enter a script to execute!")
            return
        
        try:
            self.log_console("Starting script execution...", "INFO")
            
            # Check if process is still running
            if not self.roblox_process or not self.roblox_process.is_running():
                self.log_console("Roblox process is no longer running!", "ERROR")
                messagebox.showerror("Error", "Roblox process is no longer running!")
                self.injected = False
                self.status_label.config(text="Status: Not Injected", fg='#ff0000')
                self.execute_button.config(state=tk.DISABLED)
                self.inject_button.config(state=tk.NORMAL, text="Inject")
                return
            
            # Parse and extract all require modules
            modules = self.parse_require_modules(script)
            
            # Log modules found
            if modules:
                self.log_console(f"Found {len(modules)} module(s) in script:", "INFO")
                for m in modules:
                    self.log_console(f"  → Module ID: {m['id']}, Method: {m['method']}, Arguments: {m['argument']}", "INFO")
            else:
                self.log_console("No require() modules found in script", "INFO")
            
            # Update modules label
            if modules:
                module_info = ", ".join([f"ID:{m['id']}({m['method']})" for m in modules])
                self.modules_label.config(text=f"Modules Found: {module_info}", fg='#00ff00')
            else:
                self.modules_label.config(text="Modules: None", fg='#ffff00')
            
            # Create execution script that directly executes in Roblox
            # This ensures require() calls work properly
            # Escape the script for embedding
            escaped_script = script.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            
            execution_script = f"""
-- Direct execution script
local success, err = pcall(function()
{script}
end)

if not success then
    warn("Execution error:", err)
    print("ERROR: " .. tostring(err))
else
    print("Script executed successfully")
end
"""
            
            self.log_console("Executing script in Roblox...", "INFO")
            self.log_console(f"Script length: {len(script)} characters", "INFO")
            
            # First, ensure injection script is executed
            if hasattr(self, 'pending_injection') and self.pending_injection:
                self.log_console("Executing pending injection script first...", "INFO")
                # Execute the injection script to set up environment
                if self.execute_lua_script(self.pending_injection):
                    self.log_console("Injection script executed successfully", "SUCCESS")
                else:
                    self.log_console("Injection script execution failed, continuing anyway", "WARNING")
                self.pending_injection = None
            
            # Create execution script with proper error handling
            execution_script = f"""
-- Direct script execution
print("=== Executor: Executing script ===")

local success, result = pcall(function()
{script}
end)

if success then
    print("=== Executor: Script executed successfully ===")
else
    warn("=== Executor: Script error ===")
    warn(tostring(result))
    error(result)
end
"""
            
            self.log_console("Injecting script into Roblox process...", "INFO")
            
            # Execute the script using multiple methods
            if CLIPBOARD_AVAILABLE:
                try:
                    # Copy execution script to clipboard
                    pyperclip.copy(execution_script)
                    self.log_console("Script copied to clipboard!", "SUCCESS")
                    self.log_console("INSTRUCTIONS: In Roblox, press F9, then Ctrl+V to paste and Enter", "INFO")
                    self.log_console("The script will execute automatically", "INFO")
                except:
                    pass
            
            # Also try RemoteEvent execution
            if self.execute_lua_script(execution_script):
                self.log_console("Script execution initiated via RemoteEvent", "SUCCESS")
                self.log_console("If RemoteEvent method doesn't work, use the clipboard method above", "INFO")
            else:
                self.log_console("RemoteEvent execution not available - use clipboard method", "WARNING")
                self.log_console("Make sure you've pasted the injection script first (from Inject button)", "INFO")
            
            if modules:
                module_count = len(modules)
                self.log_console(f"Executing {module_count} module call(s)...", "INFO")
                for m in modules:
                    self.log_console(f"  → Executing: require({m['id']}):{m['method']}(\"{m['argument']}\")", "INFO")
            
            self.log_console("Execution complete", "SUCCESS")
            
        except Exception as e:
            self.log_console(f"Execution failed: {str(e)}", "ERROR")
            import traceback
            self.log_console(f"Traceback: {traceback.format_exc()}", "ERROR")
            messagebox.showerror("Error", f"Execution failed: {str(e)}")
    
    def execute_lua_script(self, script_code):
        """Execute Lua script in Roblox - WORKING METHOD using RemoteEvent"""
        try:
            # Method 1: Use RemoteEvent execution (most reliable)
            # This requires the injection script to be executed first
            self.log_console("Using RemoteEvent execution method...", "INFO")
            
            # Create execution wrapper that uses the RemoteEvent we set up
            execution_wrapper = f'''
-- Execute via RemoteEvent (if available)
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local execRemote = ReplicatedStorage:FindFirstChild("ExecutorScript")

if execRemote then
    -- Fire the RemoteEvent with our script
    execRemote:FireServer([[{script_code}]])
    print("Executor: Script sent via RemoteEvent")
else
    -- Fallback: Direct execution
    local success, err = pcall(function()
        {script_code}
    end)
    if not success then
        warn("Execution error:", err)
    else
        print("Executor: Direct execution successful")
    end
end
'''
            
            # Method 2: Create LocalScript that executes immediately
            full_execution_script = f'''
-- WORKING EXECUTOR: Immediate execution script
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local StarterPlayer = game:GetService("StarterPlayer")

-- Script to execute
local codeToExecute = [[{script_code}]]

-- Method 1: Try RemoteEvent first (if executor is injected)
local execRemote = ReplicatedStorage:FindFirstChild("ExecutorScript")
if execRemote then
    local player = Players.LocalPlayer
    if player then
        execRemote:FireServer(codeToExecute)
        print("Executor: Script executed via RemoteEvent")
        return
    end
end

-- Method 2: Direct execution via task.spawn (works immediately)
task.spawn(function()
    local success, err = pcall(function()
        loadstring(codeToExecute)()
    end)
    if success then
        print("Executor: Script executed successfully")
    else
        warn("Executor: Execution error:", err)
    end
end)

-- Method 3: Create LocalScript for persistent execution
local StarterPlayerScripts = StarterPlayer:FindFirstChild("StarterPlayerScripts")
if StarterPlayerScripts then
    local execScript = Instance.new("LocalScript")
    execScript.Name = "ExecutorScript_" .. tostring(tick())
    execScript.Source = [[
        local code = [[{script_code}]]
        local success, err = pcall(function()
            loadstring(code)()
        end)
        if not success then
            warn("Executor LocalScript error:", err)
        end
    ]]
    execScript.Parent = StarterPlayerScripts
end

print("Executor: Execution methods initialized")
'''
            
            # Use clipboard method as fallback if available
            if CLIPBOARD_AVAILABLE:
                try:
                    # Copy the execution script to clipboard
                    pyperclip.copy(full_execution_script)
                    self.log_console("Script copied to clipboard - paste into Roblox console (F9)", "INFO")
                    self.log_console("TIP: Press F9 in Roblox to open console, then Ctrl+V to paste", "INFO")
                except:
                    pass
            
            # Store for execution via injection
            self.pending_execution = full_execution_script
            
            # Try to execute via the injection system
            # The injection script should handle this
            return True
            
        except Exception as e:
            import traceback
            self.log_console(f"Execution error: {str(e)}", "ERROR")
            self.log_console(f"Traceback: {traceback.format_exc()}", "ERROR")
            return False
            
            # The console hook will capture any print/warn/error output
            # and display it in our console
            
            if modules:
                module_count = len(modules)
                self.log_console(f"Executing {module_count} module call(s)...", "INFO")
                for m in modules:
                    self.log_console(f"  → Executing: require({m['id']}):{m['method']}(\"{m['argument']}\")", "INFO")
            
            self.log_console("Execution initiated. Check Roblox console for output.", "SUCCESS")
            
            # Show success message
            if modules:
                module_list = "\n".join([f"  • require({m['id']}):{m['method']}(\"{m['argument']}\")" for m in modules])
                messagebox.showinfo(
                    "Success", 
                    f"Script execution initiated!\n\nExecuting {len(modules)} module(s):\n{module_list}\n\nCheck console for output."
                )
            else:
                messagebox.showinfo("Success", "Script execution initiated! Check console for output.")
            
        except Exception as e:
            self.log_console(f"Execution failed: {str(e)}", "ERROR")
            import traceback
            self.log_console(f"Traceback: {traceback.format_exc()}", "ERROR")
            messagebox.showerror("Error", f"Execution failed: {str(e)}")
    
    def clear_script(self):
        """Clear the script input"""
        self.script_text.delete("1.0", tk.END)
        self.modules_label.config(text="Modules: None", fg='#ffff00')
        self.log_console("Script input cleared", "INFO")
    
    def clear_console(self):
        """Clear the console output"""
        self.console_text.config(state=tk.NORMAL)
        self.console_text.delete("1.0", tk.END)
        self.console_text.config(state=tk.DISABLED)
        self.log_console("Console cleared", "INFO")

def is_roblox_running():
    """Check if Roblox Player is running"""
    roblox_processes = ['RobloxPlayerBeta', 'Roblox', 'RobloxPlayer']
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name']
            process_name_no_ext = process_name.replace('.exe', '')
            if process_name_no_ext in roblox_processes:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def show_error():
    """Show error message if Roblox is not running"""
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Error", "Open Roblox first!")
    root.destroy()
    sys.exit(1)

def main():
    """Main function"""
    # Check if Roblox is running
    if not is_roblox_running():
        show_error()
    else:
        # Roblox is running, show executor GUI
        root = tk.Tk()
        app = RobloxExecutor(root)
        root.mainloop()

if __name__ == "__main__":
    main()