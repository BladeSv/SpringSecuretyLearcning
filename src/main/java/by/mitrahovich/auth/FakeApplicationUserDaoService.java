package by.mitrahovich.auth;

import static by.mitrahovich.securety.ApplicationUserRole.ADMIN;
import static by.mitrahovich.securety.ApplicationUserRole.ADMINTRAINEE;
import static by.mitrahovich.securety.ApplicationUserRole.STUDENT;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

	private final PasswordEncoder passwordEncoder;

	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		super();
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {

		return getApplicationUsers().stream().filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}

	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser("anna", passwordEncoder.encode("pas"), STUDENT.getGrantedAuthority(), true, true,
						true, true),
				new ApplicationUser("linda", passwordEncoder.encode("pas"), ADMIN.getGrantedAuthority(), true, true,
						true, true),
				new ApplicationUser("tom", passwordEncoder.encode("pas"), ADMINTRAINEE.getGrantedAuthority(), true,
						true, true, true));

		return applicationUsers;

	}

}
