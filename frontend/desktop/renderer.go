// Framebuffer shader and upload path adapted from CrumbleCracker (Apache-2.0).
package desktop

import (
	"fmt"
	"github.com/tinyrange/gowin/gl"
	"image"
	"unsafe"
)

const (
	displayVertexShader = `#version 150
in vec2 position;
in vec2 texcoord;
out vec2 uv;
void main() {
	uv = texcoord;
	gl_Position = vec4(position, 0.0, 1.0);
}`
	displayFragmentShader = `#version 150
uniform sampler2D framebuffer;
uniform bool flipY;
in vec2 uv;
out vec4 color;
void main() {
	vec2 samplePosition = uv;
	if (flipY) {
		samplePosition.y = 1.0 - samplePosition.y;
	}
	color = texture(framebuffer, samplePosition);
}`
)

func compileDisplayProgram(api gl.OpenGL) (uint32, error) {
	return compileGraphicsProgram(api, displayFragmentShader)
}

func compileGraphicsProgram(api gl.OpenGL, fragmentSource string) (uint32, error) {
	compile := func(kind uint32, source string) (uint32, error) {
		shader := api.CreateShader(kind)
		api.ShaderSource(shader, source)
		api.CompileShader(shader)
		var status int32
		api.GetShaderiv(shader, gl.CompileStatus, &status)
		if status == 0 {
			detail := api.GetShaderInfoLog(shader)
			api.DeleteShader(shader)
			return 0, fmt.Errorf("compile graphics shader: %s", detail)
		}
		return shader, nil
	}
	vertex, err := compile(gl.VertexShader, displayVertexShader)
	if err != nil {
		return 0, err
	}
	defer api.DeleteShader(vertex)
	fragment, err := compile(gl.FragmentShader, fragmentSource)
	if err != nil {
		return 0, err
	}
	defer api.DeleteShader(fragment)
	program := api.CreateProgram()
	api.AttachShader(program, vertex)
	api.AttachShader(program, fragment)
	api.LinkProgram(program)
	var status int32
	api.GetProgramiv(program, gl.LinkStatus, &status)
	if status == 0 {
		detail := api.GetProgramInfoLog(program)
		api.DeleteProgram(program)
		return 0, fmt.Errorf("link graphics program: %s", detail)
	}
	return program, nil
}

type renderer struct {
	gl                         gl.OpenGL
	program, vao, vbo, texture uint32
	width, height              int
}

func newRenderer(api gl.OpenGL) (r *renderer, err error) {
	r = &renderer{gl: api}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	r.program, err = compileDisplayProgram(api)
	if err != nil {
		return nil, err
	}
	vertices := []float32{-1, 1, 0, 0, -1, -1, 0, 1, 1, -1, 1, 1, -1, 1, 0, 0, 1, -1, 1, 1, 1, 1, 1, 0}
	api.GenVertexArrays(1, &r.vao)
	api.GenBuffers(1, &r.vbo)
	api.BindVertexArray(r.vao)
	api.BindBuffer(gl.ArrayBuffer, r.vbo)
	api.BufferData(gl.ArrayBuffer, len(vertices)*4, unsafe.Pointer(&vertices[0]), gl.StaticDraw)
	for i, name := range []string{"position", "texcoord"} {
		loc := api.GetAttribLocation(r.program, name)
		if loc < 0 {
			return r, fmt.Errorf("missing attribute %s", name)
		}
		api.VertexAttribPointer(uint32(loc), 2, gl.Float, false, 16, uintptr(i*8))
		api.EnableVertexAttribArray(uint32(loc))
	}
	api.GenTextures(1, &r.texture)
	api.ActiveTexture(gl.Texture0)
	api.BindTexture(gl.Texture2D, r.texture)
	api.TexParameteri(gl.Texture2D, gl.TextureMinFilter, gl.Linear)
	api.TexParameteri(gl.Texture2D, gl.TextureMagFilter, gl.Linear)
	api.TexParameteri(gl.Texture2D, gl.TextureWrapS, gl.ClampToEdge)
	api.TexParameteri(gl.Texture2D, gl.TextureWrapT, gl.ClampToEdge)
	api.UseProgram(r.program)
	api.Uniform1i(api.GetUniformLocation(r.program, "framebuffer"), 0)
	api.Uniform1i(api.GetUniformLocation(r.program, "flipY"), 0)
	return r, nil
}
func (r *renderer) upload(frame *image.RGBA) {
	if frame == nil || frame.Rect.Empty() {
		return
	}
	api := r.gl
	w, h := frame.Rect.Dx(), frame.Rect.Dy()
	api.ActiveTexture(gl.Texture0)
	api.BindTexture(gl.Texture2D, r.texture)
	api.PixelStorei(gl.UnpackAlignment, 1)
	if w != r.width || h != r.height {
		api.TexImage2D(gl.Texture2D, 0, int32(gl.RGBA), int32(w), int32(h), 0, gl.RGBA, gl.UnsignedByte, nil)
		r.width, r.height = w, h
	}
	// Capture owns its bytes. Respect padded/subimage rows rather than assuming stride.
	if frame.Stride == w*4 {
		api.TexSubImage2D(gl.Texture2D, 0, 0, 0, int32(w), int32(h), gl.RGBA, gl.UnsignedByte, unsafe.Pointer(&frame.Pix[0]))
	} else {
		for y := 0; y < h; y++ {
			api.TexSubImage2D(gl.Texture2D, 0, 0, int32(y), int32(w), 1, gl.RGBA, gl.UnsignedByte, unsafe.Pointer(&frame.Pix[y*frame.Stride]))
		}
	}
}
func (r *renderer) draw(w, h int) {
	api := r.gl
	api.Viewport(0, 0, int32(w), int32(h))
	api.ClearColor(0.025, 0.035, 0.055, 1)
	api.Clear(gl.ColorBufferBit)
	if r.width == 0 || w <= 0 || h <= 0 {
		return
	}
	rect := viewport(w, h, r.width, r.height)
	api.Viewport(int32(rect.Min.X), int32(h-rect.Max.Y), int32(rect.Dx()), int32(rect.Dy()))
	api.UseProgram(r.program)
	api.BindVertexArray(r.vao)
	api.ActiveTexture(gl.Texture0)
	api.BindTexture(gl.Texture2D, r.texture)
	api.DrawArrays(gl.Triangles, 0, 6)
}
func (r *renderer) close() {
	if r == nil {
		return
	}
	a := r.gl
	if r.texture != 0 {
		a.DeleteTextures(1, &r.texture)
	}
	if r.vbo != 0 {
		a.DeleteBuffers(1, &r.vbo)
	}
	if r.vao != 0 {
		a.DeleteVertexArrays(1, &r.vao)
	}
	if r.program != 0 {
		a.DeleteProgram(r.program)
	}
}
