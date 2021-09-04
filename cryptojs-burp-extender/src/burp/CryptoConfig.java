package burp;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;

import javax.swing.SpringLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

@SuppressWarnings("serial")
public class CryptoConfig extends JPanel {
	BurpExtender burp;
	
	private JTextField textField;
	private JTextField textField_1;

	/**
	 * Create the panel.
	 */
	public CryptoConfig(BurpExtender b) {
		this.burp = b;
		SpringLayout springLayout = new SpringLayout();
		setLayout(springLayout);
		
		JLabel lblCryptojsAesPassphrase = new JLabel("CryptoJS AES Passphrase");
		springLayout.putConstraint(SpringLayout.NORTH, lblCryptojsAesPassphrase, 15, SpringLayout.NORTH, this);
		springLayout.putConstraint(SpringLayout.WEST, lblCryptojsAesPassphrase, 10, SpringLayout.WEST, this);
		add(lblCryptojsAesPassphrase);
		
		textField = new JTextField();
		springLayout.putConstraint(SpringLayout.NORTH, textField, -2, SpringLayout.NORTH, lblCryptojsAesPassphrase);
		springLayout.putConstraint(SpringLayout.WEST, textField, 6, SpringLayout.EAST, lblCryptojsAesPassphrase);
		add(textField);
		textField.setColumns(10);
		
		JButton btnSetPassphrase = new JButton("Set Passphrase");
		btnSetPassphrase.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				b.stdout.write("old passphrase is " + b.passphrase + "\n");
				b.passphrase = textField.getText().trim();
//				re-register the editor tab to use the new passphrase
				b.callbacks.registerMessageEditorTabFactory(b);
				b.stdout.write("new passphrase is " + b.passphrase + "\n");
				b.stdout.flush();
			}
		});
		springLayout.putConstraint(SpringLayout.NORTH, btnSetPassphrase, -5, SpringLayout.NORTH, lblCryptojsAesPassphrase);
		springLayout.putConstraint(SpringLayout.WEST, btnSetPassphrase, 6, SpringLayout.EAST, textField);
		
		add(btnSetPassphrase);
		
		JLabel lblParameterName = new JLabel("Parameter Name");
		springLayout.putConstraint(SpringLayout.NORTH, lblParameterName, 16, SpringLayout.SOUTH, lblCryptojsAesPassphrase);
		springLayout.putConstraint(SpringLayout.WEST, lblParameterName, 0, SpringLayout.WEST, lblCryptojsAesPassphrase);
		add(lblParameterName);
		
		textField_1 = new JTextField();
		springLayout.putConstraint(SpringLayout.NORTH, textField_1, -2, SpringLayout.NORTH, lblParameterName);
		springLayout.putConstraint(SpringLayout.WEST, textField_1, 0, SpringLayout.WEST, textField);
		add(textField_1);
		textField_1.setColumns(10);
		
		JButton btnSetParameterName = new JButton("Set Parameter Name");
		springLayout.putConstraint(SpringLayout.NORTH, btnSetParameterName, -5, SpringLayout.NORTH, lblParameterName);
		springLayout.putConstraint(SpringLayout.WEST, btnSetParameterName, 6, SpringLayout.EAST, textField_1);
		btnSetParameterName.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				b.stdout.write("old parameter is " + b.paramName + "\n");
				b.paramName = textField_1.getText().trim();
//				re-register the editor tab to use the new paramname
				b.callbacks.registerMessageEditorTabFactory(b);
				b.stdout.write("new parameter is " + b.paramName + "\n");
				b.stdout.flush();
			}
		});
		add(btnSetParameterName);

	}
}
