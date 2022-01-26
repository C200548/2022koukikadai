package jp.ac.ccmc._2x.kimatsu2021;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class MainController {

	@Autowired
	private AccountService service;

	@GetMapping("/")
	public String viewHomaPage(Model model) {
		List<Account> listAccounts = service.listAll();
		model.addAttribute("listAccounts", listAccounts);
		return "index";
	}

	@GetMapping("/new")
	public String showNewAccountPage(Model model) {
		Account account = new Account();
		model.addAttribute("account", account);
		return "new";
	}

	@PostMapping("/new")
	public String createAccount(@ModelAttribute("account") Account account, RedirectAttributes redirectAttributes) {
		service.save(account);
        String message = "#" + account.getId() + "「" + account.getName() + "」を新規作成しました。";
        redirectAttributes.addFlashAttribute("message", message);
		return "redirect:/";
	}

	@GetMapping("/edit/{id}")
	public String showEditAccountPage(@PathVariable(name="id") int id, Model model) {
		Account account = service.get(id);
		model.addAttribute("account", account);
		return "edit";
	}

	@PostMapping("/edit")
	public String saveEditData(@ModelAttribute("account") Account account, RedirectAttributes redirectAttributes) {
		service.save(account);
        String message = "#" + account.getId() + "「" + account.getName() + "」を編集しました。";
        redirectAttributes.addFlashAttribute("message", message);
		return "redirect:/";
	}

	@GetMapping("/delete/{id}")
	public String showDeleteAccountPage(@PathVariable(name="id") int id, Model model) {
		Account account = service.get(id);
		model.addAttribute("account", account);
        return "delete";
	}

	@PostMapping("/delete")
	public String deleteAccount(@ModelAttribute("account") Account account, RedirectAttributes redirectAttributes) {
		service.delete(account.getId());
		String message = "#" + account.getId() + "「" + account.getName() + "」を削除しました。";
        redirectAttributes.addFlashAttribute("message", message);
		return "redirect:/";
	}

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}