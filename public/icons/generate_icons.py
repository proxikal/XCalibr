#!/usr/bin/env python3
"""
XCalibr Icon Generator
Generates PNG icons for the browser extension
"""

try:
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("PIL/Pillow not available. Install with: pip3 install Pillow")
    print("Or use the generate-icons.html file in your browser instead.")
    exit(1)

def create_icon(size):
    """Create an icon of the specified size"""
    # Create image with dark background
    img = Image.new('RGB', (size, size), color='#0f172a')
    draw = ImageDraw.Draw(img)

    # Calculate scaled dimensions
    scale = size / 128
    padding = int(size * 0.25)
    inner_size = int(size * 0.5)

    # Draw terminal window (rounded rectangle background)
    terminal_color = '#1e293b'
    green_color = '#00e600'

    # Draw filled rectangle for terminal
    draw.rectangle(
        [padding, padding, padding + inner_size, padding + inner_size],
        fill=terminal_color,
        outline=green_color,
        width=max(1, int(scale * 2))
    )

    # Draw prompt symbol (>)
    prompt_x = padding + int(inner_size * 0.1875)
    prompt_y = padding + int(inner_size * 0.3125)
    prompt_size = int(inner_size * 0.25)
    line_width = max(1, int(scale * 3))

    # Draw > symbol
    draw.line(
        [(prompt_x, prompt_y),
         (prompt_x + prompt_size, prompt_y + prompt_size)],
        fill=green_color,
        width=line_width
    )
    draw.line(
        [(prompt_x + prompt_size, prompt_y + prompt_size),
         (prompt_x, prompt_y + prompt_size * 2)],
        fill=green_color,
        width=line_width
    )

    # Draw cursor line
    cursor_x = prompt_x + prompt_size + int(scale * 8)
    cursor_y = prompt_y + prompt_size
    draw.line(
        [(cursor_x, cursor_y), (cursor_x + prompt_size, cursor_y)],
        fill=green_color,
        width=line_width
    )

    return img

def main():
    """Generate all icon sizes"""
    sizes = [16, 32, 48, 128]

    for size in sizes:
        print(f"Generating icon{size}.png...")
        icon = create_icon(size)
        icon.save(f'icon{size}.png', 'PNG')
        print(f"  ✓ Saved icon{size}.png")

    print("\nAll icons generated successfully!")
    print("Icons are ready to use with the extension.")

if __name__ == '__main__':
    main()
