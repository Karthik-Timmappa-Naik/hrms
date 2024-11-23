package com.magadhUniversity.service;

import com.magadhUniversity.model.Subject;
import java.util.List;

public interface SubjectService {
    Subject createSubject(Subject subject);
    List<Subject> getAllSubjects();
    Subject updateSubject(Long subjectId, Subject subject);
    void deleteSubject(Long subjectId);
}
