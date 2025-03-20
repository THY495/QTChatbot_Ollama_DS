import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
import requests
import re
from datetime import datetime


class EnhancedStreamParser:
    def __init__(self):
        self.buffer = ""
        self.in_think = False
        self.current_think = ""
        self.think_stack = []

    def feed(self, chunk):
        self.buffer += chunk
        output = []
        thinks = []

        while True:
            if not self.in_think:
                start = self.buffer.find("<think>")
                if start == -1:
                    output.append(self.buffer)
                    self.buffer = ""
                    break

                output.append(self.buffer[:start])
                self.buffer = self.buffer[start + 7:]
                self.in_think = True

            if self.in_think:
                end = self.buffer.find("</think>")
                if end == -1:
                    self.current_think += self.buffer
                    self.buffer = ""
                    break

                self.current_think += self.buffer[:end]
                self.buffer = self.buffer[end + 8:]
                self.think_stack.append(self.current_think)
                thinks.append(self.current_think)
                self.current_think = ""
                self.in_think = False

        return "".join(output), thinks


class EnhancedChatApp:
    def __init__(self, master):
        self.master = master
        master.title("DeepSeek-R1 Chat")
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("Think.TLabelframe", foreground="#FF4500")

        # 初始化状态变量
        self.collapsed_sections = {}
        self.think_blocks = []
        self.current_think_id = 0

        # 创建界面组件
        self.create_widgets()
        self.create_menu()
        self.setup_highlight_tags()

    def create_widgets(self):
        # 主容器
        main_frame = ttk.Frame(self.master)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # 用户消息区（左）
        self.user_frame = ttk.LabelFrame(main_frame, text="对话历史")
        self.user_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        self.user_display = self.create_display(self.user_frame)

        # AI响应区（中）
        self.ai_frame = ttk.LabelFrame(main_frame, text="AI回复")
        self.ai_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        self.ai_display = self.create_display(self.ai_frame)

        # 思考过程区（右）
        self.think_frame = ttk.LabelFrame(main_frame, text="思考过程", style="Think.TLabelframe")
        self.think_frame.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")
        self.think_display = self.create_display(self.think_frame, bg="#FFF8E7")
        self.think_display.bind("<Button-3>", self.show_context_menu)

        # 输入区域
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="ew")

        self.input_entry = ttk.Entry(input_frame, width=100)
        self.input_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.input_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = ttk.Button(input_frame, text="发送", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)

        # 控制按钮
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, columnspan=3, pady=5, sticky="ew")

        ttk.Button(control_frame, text="清空对话", command=self.clear_chat).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="折叠全部", command=lambda: self.toggle_all_folds(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="展开全部", command=lambda: self.toggle_all_folds(False)).pack(side=tk.LEFT, padx=5)

        # 布局配置
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(2, weight=1)
        main_frame.rowconfigure(0, weight=1)

    def create_display(self, parent, bg="white"):
        display = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            width=35,
            height=25,
            font=('微软雅黑', 10),
            bg=bg
        )
        display.pack(fill=tk.BOTH, expand=True)
        display.configure(state='disabled')
        return display

    def create_menu(self):
        menubar = tk.Menu(self.master)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="保存思考日志", command=self.save_think_log)
        file_menu.add_command(label="导出对话记录", command=self.export_chat_history)
        menubar.add_cascade(label="文件", menu=file_menu)

        # 编辑菜单
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="清空所有记录", command=self.clear_all_history)
        menubar.add_cascade(label="编辑", menu=edit_menu)

        self.master.config(menu=menubar)

    def setup_highlight_tags(self):
        # 语法高亮标签
        self.think_display.tag_configure("keyword", foreground="blue")
        self.think_display.tag_configure("error", foreground="red")
        self.think_display.tag_configure("collapsed", foreground="gray", font=('Consolas', 9, 'italic'))
        self.think_display.tag_configure("fold_marker", foreground="green", underline=1)
        self.think_display.tag_bind("fold_marker", "<Button-1>", self.toggle_fold)

    def send_message(self):
        self._clear_think()
        user_input = self.input_entry.get().strip()
        if not user_input:
            return

        self.update_display("user", f"你：{user_input}\n\n")
        self.input_entry.delete(0, tk.END)
        threading.Thread(target=self.process_response, args=(user_input,)).start()

    def process_response(self, prompt):
        try:
            parser = EnhancedStreamParser()
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "deepseek-r1",
                    "prompt": prompt,
                    "stream": True
                },
                stream=True
            )
            response.raise_for_status()

            for line in response.iter_lines():
                if line:
                    chunk = json.loads(line)
                    if 'response' in chunk:
                        visible_content, think_contents = parser.feed(chunk['response'])

                        if visible_content:
                            self.master.after(0, self.update_ai_stream, visible_content)

                        for think in think_contents:
                            self.master.after(0, self.add_think_block, think)

            self.master.after(0, self.finalize_response)

        except Exception as e:
            self.master.after(0, self.show_error, f"错误：{str(e)}")

    def add_think_block(self, content):
        self.current_think_id += 1
        block_id = self.current_think_id

        # 记录原始内容
        self.think_blocks.append((block_id, content))

        # 插入折叠标记
        start = self.think_display.index(tk.END)
        self.think_display.configure(state='normal')
        self.think_display.insert(tk.END, f"▶ 思考过程 ...\n", "fold_marker")
        end = self.think_display.index(tk.END)

        # 存储折叠状态
        self.collapsed_sections[block_id] = (start, end, True)

        # 插入实际内容（初始隐藏）
        self.think_display.insert(tk.END, f"{content}\n\n", ("keyword",))
        self.think_display.configure(state='disabled')
        self.think_display.see(tk.END)

    def toggle_fold(self, event):
        index = self.think_display.index(f"@{event.x},{event.y}")
        for bid, (start, end, is_collapsed) in self.collapsed_sections.items():
            if self.think_display.compare(start, "<=", index) and self.think_display.compare(index, "<", end):
                new_state = not is_collapsed
                self.update_fold_display(bid, new_state)
                self.collapsed_sections[bid] = (start, end, new_state)
                break

    def update_fold_display(self, block_id, is_collapsed):
        start, end, _ = self.collapsed_sections[block_id]
        self.think_display.configure(state='normal')
        self.think_display.delete(start, end)

        if is_collapsed:
            display_text = f"▶ 折叠的思考块 {block_id}..."
            self.think_display.insert(start, display_text, "fold_marker")
        else:
            content = next(x[1] for x in self.think_blocks if x[0] == block_id)
            self.think_display.insert(start, f"{content}\n\n", "keyword")

        self.think_display.configure(state='disabled')

    def toggle_all_folds(self, collapse=True):
        for bid in list(self.collapsed_sections.keys()):
            self.update_fold_display(bid, collapse)
            self.collapsed_sections[bid] = (*self.collapsed_sections[bid][:2], collapse)

    def save_think_log(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("所有文件", "*.*")]
        )
        if filename:
            content = self.get_full_think_content()
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"思考日志 {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
                f.write(content)

    def get_full_think_content(self):
        return "\n".join([f"思考块 {bid}:\n{content}\n" for bid, content in self.think_blocks])

    def export_chat_history(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if filename:
            history = [
                "用户对话记录：\n" + self.user_display.get(1.0, tk.END),
                "\nAI回复记录：\n" + self.ai_display.get(1.0, tk.END),
                "\n思考过程：\n" + self.get_full_think_content()
            ]
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(history))

    def clear_all_history(self):
        for widget in [self.user_display, self.ai_display, self.think_display]:
            widget.configure(state='normal')
            widget.delete(1.0, tk.END)
            widget.configure(state='disabled')

        self.collapsed_sections.clear()
        self.think_blocks.clear()
        self.current_think_id = 0

    def show_context_menu(self, event):
        menu = tk.Menu(self.master, tearoff=0)
        menu.add_command(label="复制", command=lambda: self.copy_text(self.think_display))
        menu.add_command(label="导出选中内容", command=self.export_selection)
        menu.tk_popup(event.x_root, event.y_root)

    def copy_text(self, widget):
        try:
            text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
        except tk.TclError:
            pass

    def export_selection(self):
        try:
            text = self.think_display.get(tk.SEL_FIRST, tk.SEL_LAST)
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
            )
            if filename:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(text)
        except tk.TclError:
            messagebox.showwarning("警告", "请先选择要导出的内容")

    def update_display(self, target, text):
        widget = getattr(self, f"{target}_display")
        widget.configure(state='normal')
        widget.insert(tk.END, text)
        widget.configure(state='disabled')
        widget.see(tk.END)

    def update_ai_stream(self, text):
        self.ai_display.configure(state='normal')
        self.ai_display.insert(tk.END, text)
        self.ai_display.configure(state='disabled')
        self.ai_display.see(tk.END)

    def finalize_response(self):
        self.ai_display.see(tk.END)

    def _clear_think(self):
        self.think_display.configure(state='normal')
        self.think_display.delete(1.0, tk.END)
        self.think_display.configure(state='disabled')
        self.think_blocks.clear()
        self.collapsed_sections.clear()
        self.current_think_id = 0

    def clear_chat(self):
        self._clear_think()
        for widget in [self.user_display, self.ai_display]:
            widget.configure(state='normal')
            widget.delete(1.0, tk.END)
            widget.configure(state='disabled')

    def show_error(self, message):
        self.ai_display.configure(state='normal')
        self.ai_display.insert(tk.END, f"⚠️ {message}\n")
        self.ai_display.configure(state='disabled')
        self.ai_display.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedChatApp(root)
    root.geometry("1366x768")
    root.mainloop()