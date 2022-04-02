package staff.Start;

import staff.Service.PersonListHolder;
import staff.ServiceRepo.PersonsListHolderRepository;
import java.io.File;
import java.io.IOException;

/**
 * Точка входа в программу
 *
 * @author AAM
 **/
public class Starter {

    public static void main(String[] args) throws IOException {
        File personsFile = new File("C:\\Project\\foreign\\My_project\\src\\main\\resources\\persons.xml");
        String path =  personsFile.toString();
        PersonListHolder listOfEmployees = PersonsListHolderRepository.getListOfEmployees(personsFile);
    }

}