package org.jcryptool.visual.sig.ui.wizards;

import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;

public class ShowSig extends Shell {
	private Label txtT;
	private Label txtT_2;
	private Label txtT_1;
	private Label text;
	private Label text_1;
	private Label text_2;
	private Label txtSig;
	private Label txtLnge;
	private Label txtSignedMes;
	private Label txtLngeMes;
	private Table table;
	private TableColumn tblclmnAddress;
	private TableColumn tblclmnHex;
	private TableColumn tblclmnAscii;
	private Table table_1;
	private TableColumn tblclmnAddress_1;
	private TableColumn tblclmnHex_1;
	private TableColumn tblclmnAscii_1;
	private Label txtSigNum;

	private int sigLen = org.jcryptool.visual.sig.algorithm.Input.signature.length;
	//private String sigStrLen = Integer.toString(sigLen); //Bytes!!!!
	private int mesLen = org.jcryptool.visual.sig.algorithm.Input.data.length;
	//private String mesStrLen = Integer.toString(mesLen); //Bytes!!!!
	private Label lblNewLabel;
	private String userName;
	
	private int sLen = sigLen * 8;
	private int mLen = mesLen * 8;
	
	
	/**
	 * Create the shell.
	 * @param display
	 */
	public ShowSig(Display display, String sig) {
		super(display, SWT.CLOSE | SWT.MIN | SWT.MAX | SWT.TITLE | SWT.APPLICATION_MODAL);
		
		Composite composite = new Composite(this, SWT.NONE);
		composite.setBounds(10, 10, 485, 661);
		
		txtT = new Label(composite, SWT.READ_ONLY | SWT.WRAP);
		txtT.setText(Messages.ShowSig_ownerTitle);
		txtT.setBounds(0, 0, 176, 21);
		
		txtT_2 = new Label(composite, SWT.READ_ONLY);
		txtT_2.setText(Messages.ShowSig_keyTitle);
		txtT_2.setBounds(0, 24, 176, 21);
		
		txtT_1 = new Label(composite, SWT.READ_ONLY);
		txtT_1.setText(Messages.ShowSig_methodTitle);
		txtT_1.setBounds(0, 48, 176, 21);
		
		// get owner of the key
		if ((org.jcryptool.visual.sig.algorithm.Input.privateKey == null) && (org.jcryptool.visual.sig.algorithm.Input.key == null)) {
			userName = "-";
		} else {
			if (org.jcryptool.visual.sig.algorithm.Input.key != null) {
				userName = org.jcryptool.visual.sig.algorithm.Input.key.getContactName();
			} else {
				userName = org.jcryptool.visual.sig.algorithm.Input.privateKey.getContactName();
			}	
		}
		text = new Label(composite, SWT.READ_ONLY | SWT.WRAP);
		text.setText(userName);
		text.setBounds(182, 0, 302, 21);
		
		// get information about the key
		text_1 = new Label(composite, SWT.READ_ONLY);
		if ((org.jcryptool.visual.sig.algorithm.Input.privateKey == null) && (org.jcryptool.visual.sig.algorithm.Input.key == null)) {
			if (sig.contains("ECDSA")) {
				text_1.setText("ANSI X9.62 prime256v1 (256 bits)");
			} else {
				text_1.setText("-");
			}
		} else {
			if (org.jcryptool.visual.sig.algorithm.Input.key != null) {
				text_1.setText(org.jcryptool.visual.sig.algorithm.Input.key.getClassName());
			} else {
				text_1.setText(org.jcryptool.visual.sig.algorithm.Input.privateKey.getClassName());
			}
		}
		text_1.setBounds(182, 24, 302, 21);
		
		text_2 = new Label(composite, SWT.READ_ONLY);
		text_2.setText(sig);
		text_2.setBounds(182, 48, 302, 21);
		
		txtSig = new Label(composite, SWT.READ_ONLY);
		txtSig.setText(Messages.ShowSig_grpSignature);
		txtSig.setBounds(0, 77, 137, 21);
		
		txtLnge = new Label(composite, SWT.READ_ONLY);
		txtLnge.setText(Messages.ShowSig_lengthSig + sLen + " Bits");
		txtLnge.setBounds(0, 253, 430, 21);
		
		Group grpOption = new Group(composite, SWT.NONE);
		grpOption.setText(Messages.ShowSig_grpOption);
		grpOption.setBounds(0, 280, 484, 73);
		grpOption.setLayout(null);
		
		txtSignedMes = new Label(composite, SWT.READ_ONLY);
		txtSignedMes.setText(Messages.ShowSig_grpMessage);
		txtSignedMes.setBounds(0, 373, 137, 21);
		
		txtLngeMes = new Label(composite, SWT.READ_ONLY);
		txtLngeMes.setText(Messages.ShowSig_lengthMessage + mLen + " Bits");
		txtLngeMes.setBounds(0, 548, 430, 21);
		

		// create table to show the generated signature
		table = new Table(composite, SWT.BORDER | SWT.FULL_SELECTION);
		table.setLinesVisible(true);
		table.setHeaderVisible(true);
		table.setBounds(0, 98, 484, 151);
		
		tblclmnAddress = new TableColumn(table, SWT.NONE);
		tblclmnAddress.setResizable(false);
		tblclmnAddress.setWidth(60);
		tblclmnAddress.setToolTipText("");
		tblclmnAddress.setText(Messages.ShowSig_tblAdr);
		
		tblclmnHex = new TableColumn(table, SWT.NONE);
		tblclmnHex.setResizable(false);
		tblclmnHex.setWidth(250);
		tblclmnHex.setText(Messages.ShowSig_tblHex);
		
		tblclmnAscii = new TableColumn(table, SWT.NONE);
		tblclmnAscii.setResizable(false);
		tblclmnAscii.setWidth(150);
		tblclmnAscii.setText(Messages.ShowSig_tblAscii);

		int stepSize = 14;
		int len1 = org.jcryptool.visual.sig.algorithm.Input.signatureHex.length();
		String asciistr = convertHexToString(org.jcryptool.visual.sig.algorithm.Input.signatureHex);
		
	    for (int i1 = 0; i1 < (Math.ceil((double)len1/(stepSize*2))) ; i1++) {
	        TableItem item = new TableItem(table, SWT.NONE);
	        
	        // column 1 - address
	        item.setText(0, getAddress(i1, stepSize));
	        
	        // column 2 - hex
	        int start1 = i1 * (stepSize*2);
	        int end1 = i1 * (stepSize*2) + (stepSize*2);
	        end1 = end1 >= len1 ? len1 : end1;
	    
	        StringBuffer bufferS1 = new StringBuffer();
	        for (int m1 = 0; m1 < (end1-start1)/2 ; m1++){
	        	bufferS1.append(org.jcryptool.visual.sig.algorithm.Input.signatureHex.charAt((2*m1)+start1));
	        	bufferS1.append(org.jcryptool.visual.sig.algorithm.Input.signatureHex.charAt((2*m1+1)+start1));
	        	bufferS1.append(" ");
	        }
	        item.setText(1, bufferS1.toString());
	               
	        // column 3 - ascii
	        StringBuffer bufferS2 = new StringBuffer();
	        bufferS2.append(asciistr, start1/2, end1/2);
	        item.setText(2, bufferS2.toString());
	      }
	    
		// create table to show signed message
		table_1 = new Table(composite, SWT.BORDER | SWT.FULL_SELECTION);
		table_1.setLinesVisible(true);
		table_1.setHeaderVisible(true);
		table_1.setBounds(0, 394, 484, 150);
		
		tblclmnAddress_1 = new TableColumn(table_1, SWT.NONE);
		tblclmnAddress_1.setResizable(false);
		tblclmnAddress_1.setWidth(60);
		tblclmnAddress_1.setToolTipText("");
		tblclmnAddress_1.setText(Messages.ShowSig_tblAdr);
		
		tblclmnHex_1 = new TableColumn(table_1, SWT.NONE);
		tblclmnHex_1.setResizable(false);
		tblclmnHex_1.setWidth(250);
		tblclmnHex_1.setText(Messages.ShowSig_tblHex);
		
		tblclmnAscii_1 = new TableColumn(table_1, SWT.NONE);
		tblclmnAscii_1.setResizable(false);
		tblclmnAscii_1.setWidth(150);
		tblclmnAscii_1.setText(Messages.ShowSig_tblAscii);  
	    
		int len2 = org.jcryptool.visual.sig.algorithm.Input.dataHex.length();
		String asciistr2 = convertHexToString(org.jcryptool.visual.sig.algorithm.Input.dataHex);

		// for (int i2 = 0; i2 < (Math.ceil((double)len2/(stepSize*2))) ; i2++) { // to show the hole message
		// shows only 6 rows - optimize performance
		for (int i2 = 0; i2 < 6 ; i2++) {
	        TableItem item = new TableItem(table_1, SWT.NONE);
	        
	        // column 1 - address
	        item.setText(0, getAddress(i2, stepSize));
	        
	        // column 2        
	        int start2 = i2 * (stepSize*2);
	        int end2 = i2 * (stepSize*2) + (stepSize*2);
	        end2 = end2 >= len2 ? len2 : end2;
	    
	        StringBuffer bufferD1 = new StringBuffer();
	        for (int n1 = 0; n1 < (end2-start2)/2 ; n1++){
	        	bufferD1.append(org.jcryptool.visual.sig.algorithm.Input.dataHex.charAt((2*n1)+start2));
	        	bufferD1.append(org.jcryptool.visual.sig.algorithm.Input.dataHex.charAt((2*n1+1)+start2));
	        	bufferD1.append(" ");
	        }
	        item.setText(1, bufferD1.toString());

	        // column 3 
	        StringBuffer bufferD2 = new StringBuffer();
	        bufferD2.append(asciistr2, start2/2, end2/2);
	        item.setText(2, bufferD2.toString());

	      }
	    
		
	    // text field to show signature as hex, octal or decimal
		txtSigNum = new Label(composite, SWT.BORDER | SWT.WRAP);
		txtSigNum.setBounds(0, 98, 484, 151);
		txtSigNum.setBackground(new Color(Display.getCurrent(), 255, 255, 255));
		
		// display options
		Button btnOkt = new Button(grpOption, SWT.RADIO);
		btnOkt.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				table.setVisible(false);
				txtSigNum.setVisible(true);
				txtSigNum.setText(org.jcryptool.visual.sig.algorithm.Input.signatureOct);
			}
		});
		btnOkt.setBounds(186, 30, 70, 16);
		btnOkt.setText(Messages.ShowSig_octal);
		
		Button btnDez = new Button(grpOption, SWT.RADIO);
		btnDez.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				table.setVisible(false);
				txtSigNum.setVisible(true);
				txtSigNum.setText(hexToDecimal(org.jcryptool.visual.sig.algorithm.Input.signatureHex));
			}
		});
		btnDez.setBounds(262, 30, 80, 16);
		btnDez.setText(Messages.ShowSig_decimal);
		
		Button btnHex = new Button(grpOption, SWT.RADIO);
		btnHex.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				table.setVisible(false);
				txtSigNum.setVisible(true);
				txtSigNum.setText(org.jcryptool.visual.sig.algorithm.Input.signatureHex);
			}
		});
		btnHex.setBounds(348, 30, 70, 16);
		btnHex.setText(Messages.ShowSig_hex);

		Button btnHexdump = new Button(grpOption, SWT.RADIO);
		btnHexdump.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				txtSigNum.setVisible(false);
				table.setVisible(true);
			}
		});
		btnHexdump.setSelection(true);
		btnHexdump.setBounds(10, 30, 170, 16);
		btnHexdump.setText(Messages.ShowSig_hexDump);
		
		
		// close window
		Button btnNewButton = new Button(composite, SWT.NONE);
		btnNewButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				ShowSig.this.close();
			}
		});
		btnNewButton.setBounds(389, 633, 95, 28);
		btnNewButton.setText(Messages.ShowSig_btnClose);
		
		// open hex editor
		Button btnOpen = new Button(composite, SWT.NONE);
		btnOpen.setEnabled(false);
		btnOpen.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				// TODO
				//Call the helper function to format the output (this is madness?!)
				//saveToFile();
				openHexEditor();
			}
		});
		btnOpen.setBounds(145, 635, 140, 25);
		btnOpen.setText(Messages.ShowSig_btnOpen);
		
		Label lblTextopeneditor = new Label(composite, SWT.WRAP | SWT.CENTER);
		lblTextopeneditor.setAlignment(SWT.LEFT);
		lblTextopeneditor.setBounds(2, 584, 475, 32);
		lblTextopeneditor.setText(Messages.ShowSig_editorDescripton);
		lblTextopeneditor.setBackground(new Color(Display.getCurrent(), 255, 255, 255));
		
		lblNewLabel = new Label(composite, SWT.NONE);
		lblNewLabel.setBounds(0, 578, 484, 44);
		lblNewLabel.setBackground(new Color(Display.getCurrent(), 255, 255, 255));
		
		Button btnSave = new Button(composite, SWT.NONE);
		btnSave.setBounds(289, 633, 95, 28);
		btnSave.setText(Messages.ShowSig_btnSave);
		btnSave.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				//Open File save dialog
				FileDialog dialog = new FileDialog(Display.getCurrent().getActiveShell(), SWT.SAVE);
			    dialog.setFileName("signature_and_message");
			    String savePath = dialog.open();
				//Write the file
			    if (savePath != null) {
					try {
					      OutputStream output = null;
					      try {
					        output = new BufferedOutputStream(new FileOutputStream(savePath));
					        output.write(sLen);
					        output.write(org.jcryptool.visual.sig.algorithm.Input.signature);
					        output.write(org.jcryptool.visual.sig.algorithm.Input.data.toString().getBytes());
					      }//end try
					      finally {
					          output.close();
					        }//end finally
					    }//end try
					    catch(FileNotFoundException ex){
					    	//LogUtil.logError(SigPlugin.PLUGIN_ID, ex);
					    }//end catch
					    catch(IOException ex){
					    	//LogUtil.logError(SigPlugin.PLUGIN_ID, ex);
					    }//end catch
					MessageBox messageBox = new MessageBox(new Shell(Display.getCurrent()), SWT.ICON_INFORMATION | SWT.OK);
	                messageBox.setText(Messages.ShowSig_MessageBoxTitle); 
	                messageBox.setMessage(Messages.ShowSig_MessageBoxText);
	                messageBox.open();
			    }//end if
			}//end widgetSelected
		});
		
		createContents();	
	}

	
	/**
	 * Create contents of the shell.
	 */
	protected void createContents() {
		setText(Messages.ShowSig_title);
		setSize(512, 710);

	}

	@Override
	protected void checkSubclass() {
		// Disable the check that prevents subclassing of SWT components
	}

	/**
	 * Returns a string to get the address in the hex-dump-table.
	 * 
	 * @param i Row of table
	 * @param stepSize Difference between digits in the row.
	 * @return a string containing the address in the table
	 */
	protected String getAddress(int i, int stepSize){
		   return String.format("%05X", (i*stepSize) & 0xFFFFF);
		}
	
	/**
	 * Returns the ascii representation of an hexadecimal string.
	 * 
	 * @param hex
	 * @return a string containing the ascii representation
	 */
	public String convertHexToString(String hex){
		  StringBuilder sb = new StringBuilder();
	 
		  for( int i=0; i<hex.length()-1; i+=2 ){
	 
		      //grab the hex in pairs
		      String output = hex.substring(i, (i + 2));
		      //convert hex to decimal
		      int decimal = Integer.parseInt(output, 16);
		      //convert the decimal to character
		      sb.append((char)decimal);
		  }
		  return sb.toString();
	  }
	
	/**
	 * Returns the decimal representation of an hexadecimal string.
	 * 
	 * @param hex
	 * @return
	 */
	public String hexToDecimal(String hex) {
		 StringBuilder sb = new StringBuilder();
		
		 for( int i=0; i<hex.length()-1; i+=2 ){
		      //grab the hex in pairs
		      String output = hex.substring(i, (i + 2));
		      //convert hex to decimal
		      int decimal = Integer.parseInt(output, 16);
		      sb.append(decimal);
		  }
		  return sb.toString();
	}
	
	//Saves message + info to file...save as what? Save where?? Huh?
//	private void saveToFile () {
//		PrintStream out = null;
//		try {
//		    out = new PrintStream(new FileOutputStream("SignedMessage.txt"));
//		    out.print("Signature: " + 
//		    		org.jcryptool.visual.sig.algorithm.Input.signatureHex + 
//		    		" Signature length: " + 
//		    		sigStrLen + 
//		    		" Function: " + 
//		    		org.jcryptool.visual.sig.algorithm.Input.chosenHash + 
//		    		" Key: " + 
//		    		org.jcryptool.visual.sig.algorithm.Input.key.getClassName() +
//		    		" Owner: " +
//		    		org.jcryptool.visual.sig.algorithm.Input.key.getContactName() +
//		    		" Message: " +
//		    		new String(org.jcryptool.visual.sig.algorithm.Input.data));
//		    
//		    MessageBox messageBox = new MessageBox(new
//					Shell(Display.getCurrent()), SWT.ICON_INFORMATION | SWT.OK);
//					messageBox.setText("Saved");
//					messageBox.setMessage("Saved to "  + System.getProperty("user.dir"));
//					messageBox.open();
//		}
//		catch (Exception e){
//			e.printStackTrace();
//		}
//		finally {
//		    if (out != null) out.close();
//		}
//		
//		System.out.println("I am here: " + System.getProperty("user.dir"));
//	}
	
	private void openHexEditor() {
		
		//String str = org.jcryptool.visual.sig.algorithm.Input.signatureHex;	
	}
}
