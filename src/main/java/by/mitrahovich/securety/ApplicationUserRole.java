package by.mitrahovich.securety;

import static by.mitrahovich.securety.ApplicationUserPermission.COURSE_READ;
import static by.mitrahovich.securety.ApplicationUserPermission.COURSE_WRITE;
import static by.mitrahovich.securety.ApplicationUserPermission.STUDENT_READ;
import static by.mitrahovich.securety.ApplicationUserPermission.STUDENT_WRITE;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.google.common.collect.Sets;

public enum ApplicationUserRole {
	STUDENT(Sets.newHashSet()), ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
	ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

	private final Set<ApplicationUserPermission> permissions;

	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}

	public Set<ApplicationUserPermission> getPermissions() {
		return permissions;
	}

	public Set<SimpleGrantedAuthority> getGrantedAuthority() {
		Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
				.map(permission -> new SimpleGrantedAuthority(permission.getPermission())).collect(Collectors.toSet());

		permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

		return permissions;
	}

}
