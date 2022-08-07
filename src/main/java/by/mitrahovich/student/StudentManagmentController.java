package by.mitrahovich.student;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("managment/api/v1/students")
public class StudentManagmentController {

	private static final List<Student> STUDENTS = List.of(new Student(1, "Bond"), new Student(2, "Maria"),
			new Student(3, "Anna"));

	@GetMapping
	@PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
	public List<Student> getAllStudents() {
		return STUDENTS;
	}

	@PostMapping
	@PreAuthorize("hasAuthority('course:write')")
	public void registerNewStudent(@RequestBody Student student) {
		System.out.println(student);
	}

	@DeleteMapping(path = "{studendId}")
	@PreAuthorize("hasAuthority('course:write')")
	public void deletStudent(@PathVariable("studendId") Integer studentId) {
		System.out.println(studentId);
	}

	@PutMapping(path = "{studendId}")
	@PreAuthorize("hasAuthority('course:write')")
	public void updateStudent(@PathVariable("studendId") Integer studentId, @RequestBody Student student) {
		System.out.println(String.format("%s %s", studentId, student));
	}
}
